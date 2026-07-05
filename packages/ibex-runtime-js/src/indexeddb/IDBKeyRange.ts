/**
 * IDBKeyRange - IndexedDB Key Range
 *
 * Represents a continuous interval over keys used for selecting records.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBKeyRange
 */

import { DOMException } from './utils';

export class IDBKeyRange {
  readonly lower: any;
  readonly upper: any;
  readonly lowerOpen: boolean;
  readonly upperOpen: boolean;

  constructor(lower: any, upper: any, lowerOpen: boolean, upperOpen: boolean) {
    this.lower = lower;
    this.upper = upper;
    this.lowerOpen = lowerOpen;
    this.upperOpen = upperOpen;
  }

  /**
   * Check whether a key is within this range.
   */
  includes(key: any): boolean {
    const cmp = compareKeys;
    if (this.lower !== undefined) {
      const lowerCmp = cmp(key, this.lower);
      if (this.lowerOpen ? lowerCmp <= 0 : lowerCmp < 0) return false;
    }
    if (this.upper !== undefined) {
      const upperCmp = cmp(key, this.upper);
      if (this.upperOpen ? upperCmp >= 0 : upperCmp > 0) return false;
    }
    return true;
  }

  /**
   * Creates a key range with only a lower bound.
   */
  static lowerBound(lower: any, open = false): IDBKeyRange {
    return new IDBKeyRange(lower, undefined, open, true);
  }

  /**
   * Creates a key range with only an upper bound.
   */
  static upperBound(upper: any, open = false): IDBKeyRange {
    return new IDBKeyRange(undefined, upper, true, open);
  }

  /**
   * Creates a key range with both lower and upper bounds.
   */
  static bound(lower: any, upper: any, lowerOpen = false, upperOpen = false): IDBKeyRange {
    if (compareKeys(lower, upper) > 0) {
      throw new DOMException('lower is greater than upper', 'DataError');
    }
    return new IDBKeyRange(lower, upper, lowerOpen, upperOpen);
  }

  /**
   * Creates a key range containing a single key value.
   */
  static only(value: any): IDBKeyRange {
    return new IDBKeyRange(value, value, false, false);
  }
}

/** Whether a value is a valid IndexedDB binary key (ArrayBuffer or a view). */
function isBinaryKey(v: any): boolean {
  return v instanceof ArrayBuffer || ArrayBuffer.isView(v);
}

/**
 * Whether a value is a valid IndexedDB key: a number (not NaN), a string, a
 * valid Date, binary data, or an array of valid keys. Booleans, null,
 * undefined and plain objects are not keys.
 */
export function isValidKey(v: any): boolean {
  if (Array.isArray(v)) return v.every(isValidKey);
  if (isBinaryKey(v)) return true;
  if (typeof v === 'string') return true;
  if (v instanceof Date) return !Number.isNaN(v.getTime());
  if (typeof v === 'number') return !Number.isNaN(v);
  return false;
}

/** Raw bytes of a binary key, for byte-wise comparison. */
function binaryBytes(v: any): Uint8Array {
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
}

/**
 * Rank of a key's type in the spec ordering (ascending):
 * Number < Date < String < Binary < Array. Throws DataError for anything that
 * is not a valid key (boolean, null, undefined, NaN, plain object, ...).
 */
function keyTypeOrder(v: any): number {
  if (Array.isArray(v)) return 5;
  if (isBinaryKey(v)) return 4;
  if (typeof v === 'string') return 3;
  if (v instanceof Date) {
    if (Number.isNaN(v.getTime())) {
      throw new DOMException('Invalid Date key', 'DataError');
    }
    return 2;
  }
  if (typeof v === 'number' && !Number.isNaN(v)) return 1;
  throw new DOMException(
    'The parameter is not a valid key.',
    'DataError',
  );
}

/**
 * Compare two IndexedDB keys per the spec ordering.
 * Returns negative if a < b, positive if a > b, 0 if equal.
 * Throws a DataError DOMException if either argument is not a valid key.
 */
export function compareKeys(a: any, b: any): number {
  const ta = keyTypeOrder(a);
  const tb = keyTypeOrder(b);
  if (ta !== tb) return ta - tb;

  switch (ta) {
    case 1: // Number
      return a - b;
    case 2: // Date
      return a.getTime() - b.getTime();
    case 3: // String
      return a < b ? -1 : a > b ? 1 : 0;
    case 4: { // Binary
      const ba = binaryBytes(a);
      const bb = binaryBytes(b);
      const len = Math.min(ba.length, bb.length);
      for (let i = 0; i < len; i++) {
        if (ba[i] !== bb[i]) return ba[i] - bb[i];
      }
      return ba.length - bb.length;
    }
    case 5: { // Array
      const len = Math.min(a.length, b.length);
      for (let i = 0; i < len; i++) {
        const c = compareKeys(a[i], b[i]);
        if (c !== 0) return c;
      }
      return a.length - b.length;
    }
    default:
      return 0;
  }
}

