// ENG-22968 — regression coverage for deep-equality bugs in the ibex builtins
// (`src/builtins/assert.js` and `src/builtins/util.js`).
//
// The expected results below are the oracle values from REAL Node (v25.9.0),
// captured offline (`node -e ...`) rather than the harness's `node:assert`,
// because bun's `deepEqual` (loose) deviates from Node on a handful of the
// +0/-0 and coercion cases this fix is specifically about. Encoding Node's
// answers keeps the test authoritative and CI-safe (no `node` dependency).
//
// Findings covered:
//   #1 Coercing primitive fast path: `a === b` let deepStrictEqual(0, -0) pass;
//      the global isNaN() made a NaN equal to any NaN-coercing value ('foo',
//      undefined, {}); assert.equal(NaN, NaN) threw (opposite of Node).
//   #2 Boxed primitives (new Number/Boolean/String/BigInt/Symbol) were never
//      unwrapped, so new Number(1) deep-equalled new Number(2).
//   #3 aSeen/bSeen were pushed but never popped: a failed Set/Map candidate pair
//      lingered and made a later comparison short-circuit to `true` (false
//      positive), and the stacks grew O(n) → _hasSeenPair O(n^2).
//   #4 util.isDeepStrictEqual was a separate naive impl (no NaN, no 0/-0, Dates/
//      RegExps/Maps/Sets/prototypes ignored, no cycle detection) — now delegates
//      to the fixed assert comparator.
//
// ENG-23000 follow-up: two constructor/prototype divergences from Node that
// ENG-22968 left out of scope are now fixed in `_deepEqualObjects` — strict
// mode compares `Object.getPrototypeOf(a) === Object.getPrototypeOf(b)` (so a
// null-proto object is NOT strictly deep-equal to a plain `{}`), and loose mode
// ignores the prototype/constructor entirely (a class instance can loosely
// deep-equal a plain object with the same own enumerable props). The rows below
// encode real Node's answers directly; there is no longer a divergence table.

import { expect, test, describe } from 'bun:test';
import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const require = createRequire(import.meta.url);
const ibexAssert = require('../../../src/builtins/assert.js');

// util.isDeepStrictEqual delegates to `require("assert")._isDeepStrictEqual`.
// In the real ibex runtime that bare specifier resolves to ibex's OWN
// `src/builtins/assert.js`; under bun's test harness it would instead resolve
// to bun's built-in `node:assert`, whose deep-equality diverges from Node on a
// few cases (e.g. it treats `Object.create(null)` as equal to `{}` in strict
// mode). To exercise ibex's actual delegation — not the host's assert — load a
// fresh copy of ibex's util.js with a custom `require` that returns ibex's
// assert module, exactly as the production module registry wires it. util.js's
// only require() is for "assert".
function loadIbexUtil(): any {
  const utilPath = fileURLToPath(new URL('../../../src/builtins/util.js', import.meta.url));
  const src = readFileSync(utilPath, 'utf8');
  const moduleObj: { exports: any } = { exports: {} };
  const wiredRequire = (id: string) =>
    id === 'assert' || id === 'node:assert' ? ibexAssert : require(id);
  // CommonJS module wrapper: (exports, require, module, __filename, __dirname).
  const fn = new Function('exports', 'require', 'module', '__filename', '__dirname', src);
  fn(moduleObj.exports, wiredRequire, moduleObj, utilPath, dirname(utilPath));
  return moduleObj.exports;
}
const ibexUtil = loadIbexUtil();

// Returns true when `fn` does not throw, false when it throws an assertion
// failure. Non-assertion errors propagate (they indicate a broken test).
function passes(fn: () => void): boolean {
  try {
    fn();
    return true;
  } catch (e: any) {
    if (e && e.code === 'ERR_ASSERTION') return false;
    throw e;
  }
}

// Distinct object identities reused across the fixtures.
const X = { id: 1 };
const Y = { id: 2 };
function makeCycle() {
  const a: any = { name: 'a' };
  a.self = a;
  return a;
}

// [name, a, b, expectStrict, expectLoose, expectIsDeepStrictEqual] — expect*
// are REAL Node's does-not-throw / boolean results (true === deep-equal).
type Row = [string, unknown, unknown, boolean, boolean, boolean];

const rows: Row[] = [
  // --- Finding #1: zeros, NaN, coercion ---
  ['+0 vs -0', 0, -0, false, true, false],
  ['-0 vs -0', -0, -0, true, true, true],
  ['+0 vs +0', 0, 0, true, true, true],
  ['NaN vs NaN', NaN, NaN, true, true, true],
  ['NaN vs string', NaN, 'foo', false, false, false],
  ['NaN vs undefined', NaN, undefined, false, false, false],
  ['NaN vs empty object', NaN, {}, false, false, false],
  ['NaN vs 1', NaN, 1, false, false, false],
  ['1 vs 1', 1, 1, true, true, true],
  ['1 vs 2', 1, 2, false, false, false],
  ['"1" vs 1', '1', 1, false, true, false],
  ['null vs undefined', null, undefined, false, true, false],
  ['null vs null', null, null, true, true, true],
  ['null vs object', null, {}, false, false, false],
  ['[NaN] vs [NaN]', [NaN], [NaN], true, true, true],
  ['[0] vs [-0]', [0], [-0], false, true, false],
  ['{a:NaN} vs {a:NaN}', { a: NaN }, { a: NaN }, true, true, true],
  ['{a:0} vs {a:-0}', { a: 0 }, { a: -0 }, false, true, false],

  // --- Finding #2: boxed primitives ---
  ['Number(1) vs Number(2)', new Number(1), new Number(2), false, false, false],
  ['Number(1) vs Number(1)', new Number(1), new Number(1), true, true, true],
  ['Number(NaN) vs Number(NaN)', new Number(NaN), new Number(NaN), true, true, true],
  ['Number(0) vs Number(-0)', new Number(0), new Number(-0), false, false, false],
  ['Boolean(true) vs Boolean(false)', new Boolean(true), new Boolean(false), false, false, false],
  ['Boolean(true) vs Boolean(true)', new Boolean(true), new Boolean(true), true, true, true],
  ['String("a") vs String("b")', new String('a'), new String('b'), false, false, false],
  ['String("a") vs String("a")', new String('a'), new String('a'), true, true, true],
  ['Number(1) vs primitive 1', new Number(1), 1, false, false, false],
  ['boxed extra prop equal', Object.assign(new Number(1), { z: 1 }), Object.assign(new Number(1), { z: 1 }), true, true, true],
  ['boxed extra prop differ', Object.assign(new Number(1), { z: 1 }), Object.assign(new Number(1), { z: 2 }), false, false, false],

  // --- Finding #3: Set/Map lingering-pair false positives ---
  ['Set false-positive A', new Set([[X, 1], [X, 2]]), new Set([[Y, 2], [X, 1]]), false, false, false],
  ['Set false-positive B', new Set([[X, 2], [X, 1]]), new Set([[X, 1], [Y, 2]]), false, false, false],
  ['Set equal by value', new Set([{ v: 1 }, { v: 2 }]), new Set([{ v: 2 }, { v: 1 }]), true, true, true],
  ['Set unequal by value', new Set([{ v: 1 }, { v: 2 }]), new Set([{ v: 1 }, { v: 3 }]), false, false, false],
  ['Map object-key false-positive', new Map([[X, 1], [Y, 2]]), new Map([[Y, 2], [X, 3]]), false, false, false],
  ['Map equal', new Map([['a', { n: 1 }]]), new Map([['a', { n: 1 }]]), true, true, true],

  // --- Finding #4 targets (util delegation): Dates, RegExps, Maps, Sets, protos, cycles ---
  ['Date equal', new Date(1000), new Date(1000), true, true, true],
  ['Date differ', new Date(1000), new Date(2000), false, false, false],
  ['RegExp equal', /abc/gi, /abc/gi, true, true, true],
  ['RegExp differ source', /abc/gi, /abd/gi, false, false, false],
  ['RegExp differ flags', /abc/g, /abc/gi, false, false, false],
  ['Map differ contents', new Map([['a', 1]]), new Map([['a', 2]]), false, false, false],
  ['Set differ contents', new Set([1, 2, 3]), new Set([1, 2, 4]), false, false, false],
  ['null-proto vs plain', Object.create(null), {}, false, true, false],
  ['class instance vs plain', new (class Foo { x = 1 })(), { x: 1 }, false, true, false],
  ['cycle equal', makeCycle(), makeCycle(), true, true, true],
  ['nested equal', { a: [1, { b: 2 }], c: new Map([[1, 2]]) }, { a: [1, { b: 2 }], c: new Map([[1, 2]]) }, true, true, true],
  ['nested differ deep', { a: [1, { b: 2 }] }, { a: [1, { b: 3 }] }, false, false, false],
];

describe('assert/util deep-equality matches Node (ENG-22968, ENG-23000)', () => {
  for (const [name, a, b, expStrict, expLoose, expIsdse] of rows) {
    test(`deepStrictEqual: ${name}`, () => {
      expect(passes(() => ibexAssert.deepStrictEqual(a, b))).toBe(expStrict);
    });
    test(`deepEqual (loose): ${name}`, () => {
      expect(passes(() => ibexAssert.deepEqual(a, b))).toBe(expLoose);
    });
    test(`util.isDeepStrictEqual: ${name}`, () => {
      // Both the public util path and the internal comparator it delegates to.
      expect(ibexUtil.isDeepStrictEqual(a, b)).toBe(expIsdse);
      expect(ibexAssert._isDeepStrictEqual(a, b)).toBe(expIsdse);
    });
  }
});

// ENG-23000: focused prototype-handling coverage. Oracle values captured from
// real Node v25.9.0 (`node -e` differential run).
describe('prototype handling matches Node (ENG-23000)', () => {
  class Foo {
    x = 1;
  }
  class Bar {
    x = 1;
  }
  const proto = { shared: true };

  test('strict distinguishes null-proto from plain object', () => {
    // Node: throws (Object.getPrototypeOf === null vs Object.prototype).
    expect(passes(() => ibexAssert.deepStrictEqual(Object.create(null), {}))).toBe(false);
    expect(ibexUtil.isDeepStrictEqual(Object.create(null), {})).toBe(false);
    expect(ibexAssert._isDeepStrictEqual(Object.create(null), {})).toBe(false);
  });

  test('strict allows two null-proto objects with equal own props', () => {
    const a = Object.assign(Object.create(null), { x: 1 });
    const b = Object.assign(Object.create(null), { x: 1 });
    expect(passes(() => ibexAssert.deepStrictEqual(a, b))).toBe(true);
    expect(ibexUtil.isDeepStrictEqual(a, b)).toBe(true);
  });

  test('strict distinguishes class instance from plain object', () => {
    // Node: throws (Foo.prototype vs Object.prototype).
    expect(passes(() => ibexAssert.deepStrictEqual(new Foo(), { x: 1 }))).toBe(false);
    expect(ibexUtil.isDeepStrictEqual(new Foo(), { x: 1 })).toBe(false);
  });

  test('strict distinguishes instances of different classes', () => {
    // Node: throws (Foo.prototype vs Bar.prototype).
    expect(passes(() => ibexAssert.deepStrictEqual(new Foo(), new Bar()))).toBe(false);
  });

  test('strict equates instances sharing a custom prototype', () => {
    const a = Object.assign(Object.create(proto), { x: 1 });
    const b = Object.assign(Object.create(proto), { x: 1 });
    expect(passes(() => ibexAssert.deepStrictEqual(a, b))).toBe(true);
  });

  test('loose ignores prototype: class instance equals plain object', () => {
    // Node: equal (loose deepEqual ignores the prototype entirely).
    expect(passes(() => ibexAssert.deepEqual(new Foo(), { x: 1 }))).toBe(true);
  });

  test('loose ignores prototype: instances of different classes are equal', () => {
    expect(passes(() => ibexAssert.deepEqual(new Foo(), new Bar()))).toBe(true);
  });

  test('loose equates null-proto and plain object with equal own props', () => {
    expect(passes(() => ibexAssert.deepEqual(Object.create(null), {}))).toBe(true);
  });

  test('differing own props still fail regardless of prototype', () => {
    expect(passes(() => ibexAssert.deepEqual(new Foo(), { x: 2 }))).toBe(false);
    const differing = Object.assign(new Foo(), { x: 2 });
    expect(passes(() => ibexAssert.deepStrictEqual(new Foo(), differing))).toBe(false);
  });
});

describe('assert.equal / notEqual NaN handling (ENG-22968)', () => {
  // [a, b, equalPasses, notEqualPasses] — REAL Node results.
  const eqRows: Array<[unknown, unknown, boolean, boolean]> = [
    [NaN, NaN, true, false], // equal(NaN,NaN) passes; notEqual(NaN,NaN) throws
    [NaN, 1, false, true],
    [1, 1, true, false],
    [1, 2, false, true],
    [0, -0, true, false], // loose: 0 == -0
    ['1', 1, true, false],
    [null, undefined, true, false],
  ];
  for (const [a, b, eqPass, neqPass] of eqRows) {
    test(`equal(${String(a)}, ${String(b)})`, () => {
      expect(passes(() => ibexAssert.equal(a, b))).toBe(eqPass);
    });
    test(`notEqual(${String(a)}, ${String(b)})`, () => {
      expect(passes(() => ibexAssert.notEqual(a, b))).toBe(neqPass);
    });
  }
});

// ENG-23035 — further deep-equality gaps beyond ENG-22968/23000: Symbol
// own-keys, Error own-enumerable-properties, and array extra-props/holes.
// Oracle values captured from real Node v25.9.0 (`node -e` differential run).
// Notably, loose deepEqual does NOT compare symbol-keyed properties at all
// (verified against real Node), only deepStrictEqual does -- several rows
// below are strict-only failures for that reason.
describe('assert/util deep-equality gaps: symbols, Error props, array holes (ENG-23035)', () => {
  const s = Symbol('k');
  class FooError extends Error {}

  function errWithCode(ctor: new (msg: string) => Error, message: string, code: string): Error {
    const e = new ctor(message);
    (e as any).code = code;
    return e;
  }

  const rows: Row[] = [
    // --- Finding #1: enumerable Symbol own-keys ---
    ['symbol value differs', { [s]: 1 }, { [s]: 2 }, false, true, false],
    ['symbol key missing on b', { [s]: 1 }, {}, false, true, false],
    ['symbol key/value equal', { [s]: 1 }, { [s]: 1 }, true, true, true],

    // --- Finding #2: Error own-enumerable-properties (does not stop at message/name) ---
    ['Error same message/name, code differs', errWithCode(Error, 'x', 'E1'), errWithCode(Error, 'x', 'E2'), false, false, false],
    ['Error same message/name/code', errWithCode(Error, 'x', 'E1'), errWithCode(Error, 'x', 'E1'), true, true, true],
    ['Error vs subclass, same message/code', errWithCode(Error, 'x', 'E1'), errWithCode(FooError, 'x', 'E1'), false, true, false],
    ['Error subclass vs subclass, same message/code', errWithCode(FooError, 'x', 'E1'), errWithCode(FooError, 'x', 'E1'), true, true, true],

    // --- Finding #3: array extra non-index own-props and sparse holes ---
    ['array extra prop differs', Object.assign([1, 2], { foo: 'x' }), Object.assign([1, 2], { foo: 'y' }), false, false, false],
    ['array extra prop equal', Object.assign([1, 2], { foo: 'x' }), Object.assign([1, 2], { foo: 'x' }), true, true, true],
    ['array extra prop missing on b', Object.assign([1, 2], { foo: 'x' }), [1, 2], false, false, false],
    ['array hole vs explicit undefined', [1, , 3], [1, undefined, 3], false, false, false],
    ['array hole vs hole', [1, , 3], [1, , 3], true, true, true],
    ['array symbol value differs', Object.assign([1, 2], { [s]: 1 }), Object.assign([1, 2], { [s]: 2 }), false, true, false],
    ['array symbol key/value equal', Object.assign([1, 2], { [s]: 1 }), Object.assign([1, 2], { [s]: 1 }), true, true, true],
    ['array length-only diff (no extra own indexed props)', (() => { const a = [1, 2]; a.length = 5; return a; })(), [1, 2], false, false, false],
  ];

  for (const [name, a, b, expStrict, expLoose, expIsdse] of rows) {
    test(`deepStrictEqual: ${name}`, () => {
      expect(passes(() => ibexAssert.deepStrictEqual(a, b))).toBe(expStrict);
    });
    test(`deepEqual (loose): ${name}`, () => {
      expect(passes(() => ibexAssert.deepEqual(a, b))).toBe(expLoose);
    });
    test(`util.isDeepStrictEqual: ${name}`, () => {
      expect(ibexUtil.isDeepStrictEqual(a, b)).toBe(expIsdse);
      expect(ibexAssert._isDeepStrictEqual(a, b)).toBe(expIsdse);
    });
  }
});

describe('seen-stack pop keeps large comparisons linear (ENG-22968)', () => {
  test('20k-element comparison is fast and correct', () => {
    const n = 20000;
    const big1: Array<{ i: number }> = [];
    const big2: Array<{ i: number }> = [];
    for (let i = 0; i < n; i++) {
      big1.push({ i });
      big2.push({ i });
    }
    const start = Date.now();
    expect(ibexAssert._isDeepStrictEqual(big1, big2)).toBe(true);
    const elapsed = Date.now() - start;
    // The O(n^2) never-popped version blew up here; the fix keeps it near-linear.
    expect(elapsed).toBeLessThan(2000);

    // A mismatch deep in the array must still be caught.
    big2[n - 1] = { i: -1 };
    expect(ibexAssert._isDeepStrictEqual(big1, big2)).toBe(false);
  });
});
