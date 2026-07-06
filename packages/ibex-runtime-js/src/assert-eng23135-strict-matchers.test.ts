// ENG-23135 — regression coverage for three false-green gaps around the core
// `_deepEqual` comparator in ibex's `src/builtins/assert.js` (the comparator
// itself was fixed under ENG-22968/23000/23035; these are the surrounding
// gaps). Expected results are the oracle values from REAL Node (v25.9.0),
// captured offline with `node -e ...` — see assert-util-deep-equal.test.ts for
// why the harness's own `node:assert` is not a trustworthy oracle here.
//
// Findings covered:
//   #1 assert.throws / assert.rejects validated error-object properties with
//      LOOSE deep equality (no strict flag), so `{ statusCode: '404' }`
//      silently matched a thrown `statusCode: 404`. Node compares validation
//      properties with strict deep equality (compareExceptionKey →
//      isDeepStrictEqual).
//   #2 The Map/Set branches returned before the strict prototype check and the
//      own-enumerable-key walk, so `deepStrictEqual(new MyMap(), new Map())`
//      and `deepStrictEqual(mapWithExtraProp, new Map())` both passed. Node
//      checks the prototype (strict only) and walks own keys (both modes).
//   #3 The own-key walks checked `hasOwnProperty` on the counterpart where
//      Node requires `propertyIsEnumerable`, making deepStrictEqual(a, b)
//      pass while deepStrictEqual(b, a) threw for the same pair.
//
import { test, describe } from 'bun:test';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const ibexAssert = require('../../../src/builtins/assert.js');

// Runs `fn`; returns true when it does not throw an assertion failure.
// Non-assertion errors propagate (they indicate a broken test).
function passes(fn: () => void): boolean {
  try {
    fn();
    return true;
  } catch (e: any) {
    if (e && e.code === 'ERR_ASSERTION') return false;
    throw e;
  }
}

function expectPass(label: string, fn: () => void) {
  if (!passes(fn)) throw new Error('expected pass (Node passes): ' + label);
}

function expectFail(label: string, fn: () => void) {
  if (passes(fn)) throw new Error('expected AssertionError (Node throws): ' + label);
}

describe('assert.throws / assert.rejects use strict deep equality for validation-object properties (ENG-23135 #1)', () => {
  test('throws: loosely-equal-but-not-strictly-equal property fails', () => {
    expectFail("throws statusCode '404' vs 404", () =>
      ibexAssert.throws(() => {
        const e: any = new Error('x');
        e.statusCode = 404;
        throw e;
      }, { statusCode: '404' }));
  });

  test('throws: strictly-equal property still passes', () => {
    expectPass('throws statusCode 404 vs 404', () =>
      ibexAssert.throws(() => {
        const e: any = new Error('x');
        e.statusCode = 404;
        throw e;
      }, { statusCode: 404 }));
  });

  test('throws: RegExp-valued properties still match by test()', () => {
    expectPass('throws message regex', () =>
      ibexAssert.throws(() => { throw new Error('boom town'); }, { message: /boom/ }));
  });

  test('rejects: loosely-equal-but-not-strictly-equal property fails', async () => {
    let rejected = false;
    try {
      await ibexAssert.rejects(async () => {
        const e: any = new Error('x');
        e.statusCode = 404;
        throw e;
      }, { statusCode: '404' });
    } catch (e: any) {
      if (!e || e.code !== 'ERR_ASSERTION') throw e;
      rejected = true;
    }
    if (!rejected) throw new Error("rejects statusCode '404' vs 404 passed; Node throws");
  });

  test('rejects: strictly-equal property still passes', async () => {
    await ibexAssert.rejects(async () => {
      const e: any = new Error('x');
      e.code = 'E1';
      throw e;
    }, { code: 'E1' });
  });
});

describe('deepStrictEqual Map/Set prototype + own-property comparison (ENG-23135 #2)', () => {
  class MyMap extends Map {}
  class MySet extends Set {}

  test('strict: subclassed Map is not equal to a base Map', () => {
    expectFail('MyMap vs Map', () =>
      ibexAssert.deepStrictEqual(new MyMap(), new Map()));
    expectFail('MySet vs Set', () =>
      ibexAssert.deepStrictEqual(new MySet(), new Set()));
  });

  test('strict: same subclass on both sides still compares equal', () => {
    expectPass('MyMap vs MyMap', () =>
      ibexAssert.deepStrictEqual(new MyMap([[1, 'a']]), new MyMap([[1, 'a']])));
  });

  test('loose: subclassed Map equals a base Map (prototype check is strict-only)', () => {
    expectPass('loose MyMap vs Map', () =>
      ibexAssert.deepEqual(new MyMap(), new Map()));
  });

  test('a Map with an extra own enumerable property is not equal to a bare Map (both modes)', () => {
    const annotated: any = new Map();
    annotated.extra = 1;
    expectFail('strict Map+extra vs Map', () =>
      ibexAssert.deepStrictEqual(annotated, new Map()));
    expectFail('loose Map+extra vs Map', () =>
      ibexAssert.deepEqual(annotated, new Map()));
    expectFail('strict Map vs Map+extra (reversed)', () =>
      ibexAssert.deepStrictEqual(new Map(), annotated));
  });

  test('a Set with an extra own enumerable property is not equal to a bare Set', () => {
    const annotated: any = new Set([1]);
    annotated.extra = 1;
    expectFail('strict Set+extra vs Set', () =>
      ibexAssert.deepStrictEqual(annotated, new Set([1])));
  });

  test('Maps/Sets with matching entries and matching extra props still compare equal', () => {
    const m1: any = new Map([[1, 'a']]);
    m1.extra = { deep: true };
    const m2: any = new Map([[1, 'a']]);
    m2.extra = { deep: true };
    expectPass('Map+extra vs Map+extra', () => ibexAssert.deepStrictEqual(m1, m2));
    expectPass('object-keyed Maps', () =>
      ibexAssert.deepStrictEqual(new Map([[{ k: 1 }, 'v']]), new Map([[{ k: 1 }, 'v']])));
    const s1: any = new Set([1, 2]);
    s1.x = 9;
    const s2: any = new Set([1, 2]);
    s2.x = 9;
    expectPass('Set+extra vs Set+extra', () => ibexAssert.deepStrictEqual(s1, s2));
  });
});

describe('own-key walk requires the counterpart key to be enumerable (ENG-23135 #3)', () => {
  function makeCounterpart(): any {
    const b: any = {};
    Object.defineProperty(b, 'x', { value: 1, enumerable: false });
    b.y = 2;
    return b;
  }

  test('strict: fails in BOTH directions (was asymmetric — (a,b) passed, (b,a) threw)', () => {
    const a = { x: 1 };
    expectFail('deepStrictEqual(a, b)', () => ibexAssert.deepStrictEqual(a, makeCounterpart()));
    expectFail('deepStrictEqual(b, a)', () => ibexAssert.deepStrictEqual(makeCounterpart(), a));
  });

  test('loose: also fails (Node loose deepEqual walks enumerable own keys too)', () => {
    const a = { x: 1 };
    expectFail('deepEqual(a, b)', () => ibexAssert.deepEqual(a, makeCounterpart()));
  });

  test('arrays with a non-enumerable own extra key on the counterpart are not equal', () => {
    const a: any = [1, 2];
    a.tag = 't';
    const b: any = [1, 2];
    Object.defineProperty(b, 'tag', { value: 't', enumerable: false });
    b.other = 'o';
    expectFail('array walk (a, b)', () => ibexAssert.deepStrictEqual(a, b));
    expectFail('array walk (b, a)', () => ibexAssert.deepStrictEqual(b, a));
  });
});
