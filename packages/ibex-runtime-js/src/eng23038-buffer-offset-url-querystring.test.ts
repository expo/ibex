// Regression tests for ENG-23038 (Buffer/url/querystring Node/WHATWG parity
// gaps in Ibex-introduced code). Oracle values captured from real Node
// v25.9.0 via `node -e` differential runs (see comments per section).
//
// Findings covered:
//   #1 src/builtins/buffer.js: writeFloatLE/BE, writeDoubleLE/BE, and
//      readBig*/writeBig* did `offset = offset || 0` (mapping NaN/null/''/
//      false to 0 *before* any validation, and silently truncating a
//      fractional offset) instead of using validateOffset's normalized
//      return, so Node-invalid offsets were silently accepted.
//   #2 src/builtins/querystring.js: stringify() ran every value through
//      String(value) instead of Node's stringifyPrimitive, so objects
//      became "[object Object]", Infinity/-Infinity/NaN became those literal
//      strings, and a Symbol value would throw (Symbols cannot be
//      implicitly ToString'd) instead of Node's silent ''.
//   #3 src/builtins/url.js: the fallback (non-native) URLSearchParams
//      serializer left `! ' ( ) ~` unescaped because encodeURIComponent
//      exempts them but the WHATWG application/x-www-form-urlencoded
//      percent-encode set does not.

import { expect, test, describe } from 'bun:test';
import { createRequire } from 'module';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';

const require = createRequire(import.meta.url);

test('buffer.js stages prototype overrides without inheriting locked Object.prototype names', () => {
  const source = fs.readFileSync(
    path.resolve(import.meta.dir, '../../../src/builtins/buffer.js'),
    'utf8',
  );

  expect(source).toContain('var BufferProto = Object.create(null);');
  expect(source).not.toContain('var BufferProto = {};');
});

// ---------------------------------------------------------------------------
// Finding #1: Buffer offset validation (src/builtins/buffer.js)
// ---------------------------------------------------------------------------
describe('buffer.js: writeFloat/Double/writeBig*/readBig* offset validation (ENG-23038 #1)', () => {
  const { Buffer: Bx } = require('../../../src/builtins/buffer.js');

  // [label, run, expectThrows, expectCode?] -- oracle behavior verified
  // directly against real Node v25.9.0.
  type Row = [string, () => unknown, boolean, string?];
  const rows: Row[] = [
    ['writeDoubleLE(1.5, NaN)', () => Bx.alloc(8).writeDoubleLE(1.5, NaN), true, 'ERR_OUT_OF_RANGE'],
    ['writeDoubleBE(1.5, NaN)', () => Bx.alloc(8).writeDoubleBE(1.5, NaN), true, 'ERR_OUT_OF_RANGE'],
    ['writeFloatLE(1.5, 2.5) fractional', () => Bx.alloc(8).writeFloatLE(1.5, 2.5), true, 'ERR_OUT_OF_RANGE'],
    ['writeFloatBE(1.5, 2.5) fractional', () => Bx.alloc(8).writeFloatBE(1.5, 2.5), true, 'ERR_OUT_OF_RANGE'],
    ['writeFloatLE(1.5, null)', () => Bx.alloc(8).writeFloatLE(1.5, null as any), true, 'ERR_INVALID_ARG_TYPE'],
    ["writeFloatLE(1.5, '')", () => Bx.alloc(8).writeFloatLE(1.5, '' as any), true, 'ERR_INVALID_ARG_TYPE'],
    ['writeFloatLE(1.5, false)', () => Bx.alloc(8).writeFloatLE(1.5, false as any), true, 'ERR_INVALID_ARG_TYPE'],
    ['writeFloatLE(1.5) default offset 0', () => Bx.alloc(8).writeFloatLE(1.5), false],
    ['writeFloatLE(1.5, 4) valid non-zero offset', () => Bx.alloc(8).writeFloatLE(1.5, 4), false],
    ['writeFloatLE(1.5, 5) beyond buffer', () => Bx.alloc(8).writeFloatLE(1.5, 5), true, 'ERR_OUT_OF_RANGE'],
    ['writeBigUInt64LE(1n, NaN)', () => Bx.alloc(8).writeBigUInt64LE(1n, NaN), true, 'ERR_OUT_OF_RANGE'],
    ['writeBigUInt64BE(1n, NaN)', () => Bx.alloc(8).writeBigUInt64BE(1n, NaN), true, 'ERR_OUT_OF_RANGE'],
    ['writeBigInt64LE(-1n, NaN)', () => Bx.alloc(8).writeBigInt64LE(-1n, NaN), true, 'ERR_OUT_OF_RANGE'],
    ['writeBigInt64BE(-1n, NaN)', () => Bx.alloc(8).writeBigInt64BE(-1n, NaN), true, 'ERR_OUT_OF_RANGE'],
    ['readBigUInt64LE(NaN)', () => Bx.alloc(8).readBigUInt64LE(NaN), true, 'ERR_OUT_OF_RANGE'],
    ['readBigUInt64BE(NaN)', () => Bx.alloc(8).readBigUInt64BE(NaN), true, 'ERR_OUT_OF_RANGE'],
    ['readBigInt64LE(2.5) fractional', () => Bx.alloc(8).readBigInt64LE(2.5), true, 'ERR_OUT_OF_RANGE'],
    ['readBigInt64BE(2.5) fractional', () => Bx.alloc(8).readBigInt64BE(2.5), true, 'ERR_OUT_OF_RANGE'],
    ['writeBigInt64BE(-1n) default offset 0', () => Bx.alloc(8).writeBigInt64BE(-1n), false],
  ];

  for (const [label, run, expectThrows, expectCode] of rows) {
    test(label, () => {
      let threw: any = null;
      let result: unknown;
      try {
        result = run();
      } catch (e) {
        threw = e;
      }
      if (expectThrows) {
        expect(threw).not.toBeNull();
        if (expectCode) expect(threw.code).toBe(expectCode);
      } else {
        expect(threw).toBeNull();
        expect(result).not.toBeUndefined();
      }
    });
  }

  test('a poisoned fractional offset no longer corrupts an off = buf.writeFloatLE(x, off) loop', () => {
    // Ticket repro: writeFloatLE(1.5, 2.5) used to write at byte 2 (truncating
    // the offset) and return 6.5 -- a non-integer offset for the next call.
    const buf = Bx.alloc(16);
    expect(() => buf.writeFloatLE(1.5, 2.5)).toThrow();
  });

  test('valid round-trip through write then read still works for all four fixed writers', () => {
    const buf = Bx.alloc(32);
    expect(buf.writeFloatLE(1.25, 0)).toBe(4);
    expect(buf.readFloatLE(0)).toBeCloseTo(1.25, 5);
    expect(buf.writeDoubleBE(3.5, 4)).toBe(12);
    expect(buf.readDoubleBE(4)).toBeCloseTo(3.5, 10);
    expect(buf.writeBigUInt64LE(123456789n, 12)).toBe(20);
    expect(buf.readBigUInt64LE(12)).toBe(123456789n);
    expect(buf.writeBigInt64BE(-42n, 20)).toBe(28);
    expect(buf.readBigInt64BE(20)).toBe(-42n);
  });
});

// ---------------------------------------------------------------------------
// Finding #2: querystring.stringify (src/builtins/querystring.js)
// ---------------------------------------------------------------------------
describe('querystring.js: stringify uses Node stringifyPrimitive, not String() (ENG-23038 #2)', () => {
  const qs = require('../../../src/builtins/querystring.js');

  // Oracle values verified directly against real Node v25.9.0
  // (`require('querystring').stringify(...)`). Note: bigint DOES stringify
  // in real Node (`{a:2n}` -> "a=2"), contrary to the ticket's own stated
  // example -- verified directly, so encoded here as Node actually behaves.
  const rows: Array<[string, unknown, string]> = [
    ['non-finite numbers become empty', { a: Infinity, b: 1 }, 'a=&b=1'],
    ['-Infinity becomes empty', { a: -Infinity }, 'a='],
    ['NaN becomes empty', { a: NaN }, 'a='],
    ['plain object becomes empty', { a: { x: 1 } }, 'a='],
    ['array mixing primitives/object/bigint', { a: [1, {}, 2n] }, 'a=1&a=&a=2'],
    ['booleans stringify', { a: true, b: false }, 'a=true&b=false'],
    ['string and zero pass through', { a: 'hello', b: 0 }, 'a=hello&b=0'],
    ['function becomes empty', { a: function () {} }, 'a='],
    ['symbol becomes empty (does not throw)', { a: Symbol('x') }, 'a='],
    ['bigint stringifies', { a: 2n }, 'a=2'],
    ['negative bigint stringifies with sign', { a: -5n }, 'a=-5'],
  ];

  for (const [label, input, expected] of rows) {
    test(label, () => {
      expect(qs.stringify(input)).toBe(expected);
    });
  }

  test('a Symbol value does not throw (String(Symbol) would)', () => {
    expect(() => qs.stringify({ a: Symbol('boom') })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Finding #3: URLSearchParams under-encoding (src/builtins/url.js fallback)
// ---------------------------------------------------------------------------
// url.js has a "host" path (delegates to a spec-compliant native
// URL/URLSearchParams when available) and a "fallback" hand-written path
// (used e.g. on bare Hermes). This finding is in the fallback serializer, so
// load the module in a vm sandbox with no URL/URLSearchParams globals to
// force that path -- same technique as
// url-builtin-fixes.eng-22969.test.ts.
describe('url.js: fallback URLSearchParams.toString() percent-encodes ! \' ( ) ~ (ENG-23038 #3)', () => {
  const SRC = fs.readFileSync(
    path.join(import.meta.dir, '../../../src/builtins/url.js'),
    'utf8',
  );

  function loadFallback(): any {
    const sandbox: any = {
      module: { exports: {} },
      console,
      process,
      TextEncoder,
      TextDecoder,
      Buffer,
    };
    sandbox.globalThis = sandbox;
    vm.runInContext(SRC, vm.createContext(sandbox), { filename: 'url.js' });
    return sandbox.module.exports;
  }

  const { URLSearchParams: FbURLSearchParams } = loadFallback();

  test('fallback constructors install toString under strict primordial lockdown', () => {
    const sandbox: any = {
      module: { exports: {} },
      console,
      process,
      TextEncoder,
      TextDecoder,
      Buffer,
    };
    sandbox.globalThis = sandbox;
    const context = vm.createContext(sandbox);
    vm.runInContext(
      'Object.defineProperty(Object.prototype, "toString", { writable: false, configurable: false });',
      context,
    );
    vm.runInContext(`"use strict";\n${SRC}`, context, { filename: 'url.js' });
    expect(new sandbox.module.exports.URL('https://example.test/a').toString())
      .toBe('https://example.test/a');
    expect(new sandbox.module.exports.URLSearchParams([['a', 'b']]).toString()).toBe('a=b');
  });

  // Oracle values verified directly against real Node's URLSearchParams.
  const rows: Array<[string, [string, string][], string]> = [
    ["reserved chars ! ' ( ) ~ *", [['name', "O'Brien~(x)!"]], 'name=O%27Brien%7E%28x%29%21'],
    ['all of ! \' ( ) ~ * together', [['a', "!'()~*"]], 'a=%21%27%28%29%7E*'],
    ['space becomes +, not %20', [['a b', 'c d']], 'a+b=c+d'],
    ['unicode still percent-encoded normally', [['k', 'héllo']], 'k=h%C3%A9llo'],
    ['plain alnum/-._* untouched', [['a', '*-._ abc']], 'a=*-._+abc'],
    ['empty params serialize to empty string', [], ''],
  ];

  for (const [label, pairs, expected] of rows) {
    test(label, () => {
      expect(new FbURLSearchParams(pairs).toString()).toBe(expected);
    });
  }

  test("the dead %2A->'*' replace does not accidentally unescape a literal %2A in input", () => {
    // encodeURIComponent never emits %2A itself (it leaves '*' unescaped), so
    // this only matters if a value already contains the literal substring
    // "%2A" pre-encoding -- confirms that case still round-trips correctly
    // (the literal '%' gets escaped to %25 first).
    expect(new FbURLSearchParams([['a', '%2A']]).toString()).toBe('a=%252A');
  });
});
