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

/**
 * Compare two IndexedDB keys per the spec ordering.
 * Returns negative if a < b, positive if a > b, 0 if equal.
 */
export function compareKeys(a: any, b: any): number {
  // Type order: Array > String > Date > Number
  const typeOrder = (v: any): number => {
    if (Array.isArray(v)) return 4;
    if (typeof v === 'string') return 3;
    if (v instanceof Date) return 2;
    if (typeof v === 'number') return 1;
    return 0;
  };

  const ta = typeOrder(a);
  const tb = typeOrder(b);
  if (ta !== tb) return ta - tb;

  if (typeof a === 'number' && typeof b === 'number') {
    return a - b;
  }
  if (typeof a === 'string' && typeof b === 'string') {
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (a instanceof Date && b instanceof Date) {
    return a.getTime() - b.getTime();
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const c = compareKeys(a[i], b[i]);
      if (c !== 0) return c;
    }
    return a.length - b.length;
  }
  return 0;
}

