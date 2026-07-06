/**
 * Structured serialization for IndexedDB values and keys.
 *
 * Records are persisted into a SQLite TEXT column, so we need a lossless,
 * deterministic text encoding. Plain `JSON.stringify` silently corrupts the
 * structured-clone-compatible types IndexedDB is required to preserve: Dates
 * become ISO strings, typed arrays become `{"0":...}` plain objects, and
 * Map/Set/undefined are dropped entirely. This module round-trips those types
 * with a tagged encoding so `get()` returns a faithful clone of what `put()`
 * stored, and so Date/binary *keys* deserialize back to their real type (which
 * `compareKeys` needs in order to sort and range-filter them correctly).
 *
 * The encoding wraps special types in an object carrying a reserved tag key.
 * User objects that happen to contain that key are escaped so they round-trip
 * unambiguously.
 *
 * Separately, `encodeOrderedKey` produces an *order-preserving* text encoding
 * of a key (see the block at the bottom of this file). The tagged-JSON key
 * above is deterministic and reversible but does NOT sort lexicographically, so
 * range/order queries had to scan the whole table and filter/sort in JS. The
 * ordered encoding lets SQLite do `WHERE keyenc BETWEEN ? AND ?` and
 * `ORDER BY keyenc` in the same order IndexedDB's compareKeys() defines, so the
 * filtering and ordering push down into SQL (ENG-22999).
 */

import { DOMException } from './utils';

const TAG = '__idb_tag__';

function toByteArray(view: ArrayBufferView): number[] {
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  return Array.from(bytes);
}

/** Convert a value into a JSON-safe representation, tagging non-JSON types. */
function encode(value: any): any {
  if (value === undefined) return { [TAG]: 'undefined' };
  if (value === null) return null;

  const t = typeof value;
  if (t === 'boolean' || t === 'string') return value;
  if (t === 'number') {
    if (Number.isNaN(value)) return { [TAG]: 'number', v: 'NaN' };
    if (value === Infinity) return { [TAG]: 'number', v: 'Infinity' };
    if (value === -Infinity) return { [TAG]: 'number', v: '-Infinity' };
    return value;
  }
  if (t === 'bigint') return { [TAG]: 'bigint', v: value.toString() };

  if (value instanceof Date) return { [TAG]: 'Date', ms: value.getTime() };
  if (value instanceof RegExp) return { [TAG]: 'RegExp', source: value.source, flags: value.flags };

  if (value instanceof ArrayBuffer) {
    return { [TAG]: 'ArrayBuffer', bytes: Array.from(new Uint8Array(value)) };
  }
  if (ArrayBuffer.isView(value)) {
    // Uint8Array, Float64Array, DataView, ... — reconstruct from raw bytes so
    // every view type (including BigInt typed arrays) round-trips uniformly.
    return { [TAG]: 'View', ctor: value.constructor.name, bytes: toByteArray(value) };
  }

  if (value instanceof Map) {
    return { [TAG]: 'Map', entries: Array.from(value.entries()).map(([k, v]) => [encode(k), encode(v)]) };
  }
  if (value instanceof Set) {
    return { [TAG]: 'Set', values: Array.from(value.values()).map(encode) };
  }

  if (Array.isArray(value)) {
    return value.map(encode);
  }

  if (t === 'object') {
    const out: Record<string, any> = {};
    for (const k of Object.keys(value)) {
      out[k] = encode(value[k]);
    }
    // A plain object that itself carries the reserved tag key must be escaped
    // so decode() does not mistake it for one of our wrappers.
    if (Object.prototype.hasOwnProperty.call(value, TAG)) {
      return { [TAG]: 'object', props: out };
    }
    return out;
  }

  // functions / symbols are not structured-cloneable.
  throw new TypeError(`Value of type ${t} could not be cloned.`);
}

function decodePlainObject(obj: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const k of Object.keys(obj)) {
    out[k] = decode(obj[k]);
  }
  return out;
}

/** Inverse of encode(). */
function decode(value: any): any {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(decode);

  const tag = value[TAG];
  if (typeof tag === 'string') {
    switch (tag) {
      case 'undefined':
        return undefined;
      case 'number':
        return value.v === 'NaN' ? NaN : value.v === 'Infinity' ? Infinity : -Infinity;
      case 'bigint':
        return BigInt(value.v);
      case 'Date':
        return new Date(value.ms);
      case 'RegExp':
        return new RegExp(value.source, value.flags);
      case 'ArrayBuffer':
        return Uint8Array.from(value.bytes).buffer;
      case 'View': {
        const buf = Uint8Array.from(value.bytes).buffer;
        const Ctor = (globalThis as any)[value.ctor];
        if (!Ctor) return buf; // Unknown view type — surface the raw buffer.
        return value.ctor === 'DataView' ? new DataView(buf) : new Ctor(buf);
      }
      case 'Map':
        return new Map(value.entries.map(([k, v]: [any, any]) => [decode(k), decode(v)]));
      case 'Set':
        return new Set(value.values.map(decode));
      case 'object':
        // Escaped user object — decode its properties as a plain object.
        return decodePlainObject(value.props);
      default:
        // Unrecognized tag: treat as an ordinary object.
        return decodePlainObject(value);
    }
  }
  return decodePlainObject(value);
}

/**
 * Serialize an arbitrary structured-clone-compatible value to text for storage.
 */
export function serializeValue(value: any): string {
  return JSON.stringify(encode(value));
}

/**
 * Deserialize a value previously produced by serializeValue().
 */
export function deserializeValue(text: string): any {
  return decode(JSON.parse(text));
}

/**
 * Serialize an IndexedDB key to a canonical text form usable as a SQLite
 * primary-key column. Deterministic: equal keys always produce identical text
 * (so `WHERE key = ?` equality works), and deserializeKey() restores the key's
 * real type so compareKeys() can order it.
 */
export function serializeKey(key: any): string {
  return JSON.stringify(encode(key));
}

/**
 * Deserialize a key previously produced by serializeKey().
 */
export function deserializeKey(text: string): any {
  return decode(JSON.parse(text));
}

// ===========================================================================
// Order-preserving key encoding (ENG-22999)
//
// Produces a text string whose default SQLite (BINARY / memcmp) ordering equals
// the IndexedDB key ordering that compareKeys() implements:
//   Number < Date < String < Binary < Array
// and, within each type, the spec ordering (numeric, ms, UTF-16 code units,
// unsigned byte-wise, element-wise). This is stored in a separate `keyenc`
// column so range predicates and ORDER BY can run in SQL instead of a full JS
// scan+sort. It is intentionally NOT reversible: keys are always reconstructed
// from the tagged-JSON `key` column, so the encoding only needs to be a total,
// deterministic, order-preserving embedding — never decoded.
//
// The alphabet of a scalar (non-array) encoding is a leading type tag digit
// ('1'..'5') plus lowercase hex, i.e. only bytes >= 0x30. Arrays additionally
// use three control bytes that all sort BELOW 0x30:
//   ORD_END (0x01) terminates an array, ORD_SEP (0x02) precedes each element,
//   ORD_ESC (0x03) escapes any control byte that appears inside a nested
//   element's encoding (so a nested array's structure can't collide with its
//   parent's separators). With escaping, an element's bytes are all >= ORD_ESC,
//   so ORD_END < ORD_SEP < every element byte — which is exactly what makes the
//   element-wise + shorter-is-smaller array ordering fall out of memcmp.
// ===========================================================================

const ORD_TAG_NUMBER = '1';
const ORD_TAG_DATE = '2';
const ORD_TAG_STRING = '3';
const ORD_TAG_BINARY = '4';
const ORD_TAG_ARRAY = '5';

const ORD_END = '\x01';
const ORD_SEP = '\x02';
const ORD_ESC = '\x03';

// Reused scratch view so the double->ordered-bits transform allocates nothing.
const _ordDataView = new DataView(new ArrayBuffer(8));

function hex8(n: number): string {
  return (n >>> 0).toString(16).padStart(8, '0');
}

/**
 * Map an IEEE-754 double onto a 64-bit unsigned integer whose ordering matches
 * the numeric ordering of the doubles, rendered as 16 fixed-width hex chars.
 * Positive numbers get the sign bit set; negatives are fully inverted. -0 is
 * normalized to +0 so it collates equal to 0 (compareKeys treats them equal).
 *
 * Done with two 32-bit halves rather than BigInt/getBigUint64 so it does not
 * depend on BigInt DataView methods being present in the host engine.
 */
function encodeDoubleOrdered(value: number): string {
  let v = value;
  if (Object.is(v, -0)) v = 0;
  _ordDataView.setFloat64(0, v, false); // big-endian, platform-independent
  let hi = _ordDataView.getUint32(0, false);
  let lo = _ordDataView.getUint32(4, false);
  if (hi & 0x80000000) {
    // Negative: invert every bit so more-negative sorts smaller.
    hi = ~hi >>> 0;
    lo = ~lo >>> 0;
  } else {
    // Positive / +0: set the sign bit so it sorts above all negatives.
    hi = (hi | 0x80000000) >>> 0;
  }
  return hex8(hi) + hex8(lo);
}

function ordBinaryBytes(v: any): Uint8Array {
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
}

/**
 * Escape the array control bytes (ORD_END/ORD_SEP/ORD_ESC) inside a nested
 * element's encoding so they can't be confused with the enclosing array's
 * structure. Each control byte c (0x01..0x03) becomes ORD_ESC + (c + 0x30),
 * a two-char sequence beginning with 0x03; this per-symbol code is prefix-free
 * and order-preserving, so it preserves both ordering and the prefix relation.
 */
function ordEscape(s: string): string {
  // Fast path: scalar element encodings never contain control bytes.
  if (!/[\x01\x02\x03]/.test(s)) return s;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 1 && c <= 3) {
      out += ORD_ESC + String.fromCharCode(c + 0x30);
    } else {
      out += s[i];
    }
  }
  return out;
}

function ordThrowInvalid(): never {
  throw new DOMException('The parameter is not a valid key.', 'DataError');
}

function encodeOrderedRaw(key: any): string {
  if (typeof key === 'number') {
    if (Number.isNaN(key)) ordThrowInvalid();
    return ORD_TAG_NUMBER + encodeDoubleOrdered(key);
  }
  if (key instanceof Date) {
    const t = key.getTime();
    if (Number.isNaN(t)) ordThrowInvalid();
    return ORD_TAG_DATE + encodeDoubleOrdered(t);
  }
  if (typeof key === 'string') {
    // One fixed-width (4 hex) group per UTF-16 code unit, matching the
    // code-unit comparison compareKeys() uses for strings.
    let out = ORD_TAG_STRING;
    for (let i = 0; i < key.length; i++) {
      out += key.charCodeAt(i).toString(16).padStart(4, '0');
    }
    return out;
  }
  if (key instanceof ArrayBuffer || ArrayBuffer.isView(key)) {
    const bytes = ordBinaryBytes(key);
    let out = ORD_TAG_BINARY;
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, '0');
    }
    return out;
  }
  if (Array.isArray(key)) {
    let out = ORD_TAG_ARRAY;
    for (const el of key) {
      out += ORD_SEP + ordEscape(encodeOrderedRaw(el));
    }
    out += ORD_END;
    return out;
  }
  ordThrowInvalid();
}

/**
 * Encode an IndexedDB key to an order-preserving text form (see block comment
 * above). Throws a DataError DOMException for anything that is not a valid key,
 * mirroring compareKeys().
 */
export function encodeOrderedKey(key: any): string {
  return encodeOrderedRaw(key);
}
