// @ts-nocheck
/**
 * ES2023+ Array polyfills for Hermes engine
 *
 * - Array.prototype.toSorted()
 * - Array.prototype.toReversed()
 * - Array.prototype.with()
 * - Array.prototype.toSpliced()
 * - Array.fromAsync()
 */

/**
 * ToIntegerOrInfinity (ES abstract operation): coerce to a number, map NaN/±0 to
 * 0, preserve ±Infinity, and otherwise truncate toward zero. Array index/count
 * arguments are defined in terms of this, so a fractional index like 1.5 must
 * truncate to 1 (not stay 1.5 and silently fail every integer comparison).
 * (ENG-22984)
 */
function toIntegerOrInfinity(value: any): number {
  const n = Number(value);
  if (Number.isNaN(n)) return 0;
  if (n === Infinity || n === -Infinity) return n;
  return Math.trunc(n);
}

export function installArrayPolyfills(): void {
  // --------------------------------------------------------------------------
  // Array.prototype.toSorted (ES2023)
  // Returns a new sorted array without mutating the original.
  // --------------------------------------------------------------------------
  if (typeof Array.prototype.toSorted !== 'function') {
    Object.defineProperty(Array.prototype, 'toSorted', {
      value: function toSorted(
        this: any[],
        compareFn?: (a: any, b: any) => number,
      ): any[] {
        if (this == null) {
          throw new TypeError('Array.prototype.toSorted called on null or undefined');
        }
        const o = Object(this);
        const len = o.length >>> 0;
        const copy = new Array(len);
        for (let i = 0; i < len; i++) {
          copy[i] = o[i];
        }
        copy.sort(compareFn);
        return copy;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Array.prototype.toReversed (ES2023)
  // Returns a new reversed array without mutating the original.
  // --------------------------------------------------------------------------
  if (typeof Array.prototype.toReversed !== 'function') {
    Object.defineProperty(Array.prototype, 'toReversed', {
      value: function toReversed(this: any[]): any[] {
        if (this == null) {
          throw new TypeError('Array.prototype.toReversed called on null or undefined');
        }
        const o = Object(this);
        const len = o.length >>> 0;
        const result = new Array(len);
        for (let i = 0; i < len; i++) {
          result[i] = o[len - 1 - i];
        }
        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Array.prototype.with (ES2023)
  // Returns a new array with the element at the given index replaced.
  // --------------------------------------------------------------------------
  if (typeof (Array.prototype as any).with !== 'function') {
    Object.defineProperty(Array.prototype, 'with', {
      value: function withMethod(this: any[], index: number, value: any): any[] {
        if (this == null) {
          throw new TypeError('Array.prototype.with called on null or undefined');
        }
        const o = Object(this);
        const len = o.length >>> 0;
        const relativeIndex = toIntegerOrInfinity(index);
        const actualIndex = relativeIndex < 0 ? len + relativeIndex : relativeIndex;
        if (actualIndex < 0 || actualIndex >= len) {
          throw new RangeError(`Invalid index : ${index}`);
        }
        const result = new Array(len);
        for (let i = 0; i < len; i++) {
          result[i] = i === actualIndex ? value : o[i];
        }
        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Array.prototype.toSpliced (ES2023)
  // Returns a new array with elements added/removed at the given index.
  // --------------------------------------------------------------------------
  if (typeof Array.prototype.toSpliced !== 'function') {
    Object.defineProperty(Array.prototype, 'toSpliced', {
      value: function toSpliced(
        this: any[],
        start: number,
        deleteCount?: number,
        ...items: any[]
      ): any[] {
        if (this == null) {
          throw new TypeError('Array.prototype.toSpliced called on null or undefined');
        }
        const o = Object(this);
        const len = o.length >>> 0;

        // Normalize start (ToIntegerOrInfinity — truncate fractional indices)
        const relativeStart = toIntegerOrInfinity(start);
        let actualStart: number;
        if (relativeStart === -Infinity) {
          actualStart = 0;
        } else if (relativeStart < 0) {
          actualStart = Math.max(len + relativeStart, 0);
        } else {
          actualStart = Math.min(relativeStart, len);
        }

        // Normalize deleteCount (ToIntegerOrInfinity, then clamp to [0, len-start])
        let actualDeleteCount: number;
        if (arguments.length === 1) {
          // If called with only start, delete everything from start. An explicit
          // undefined deleteCount is present and therefore deletes zero.
          actualDeleteCount = len - actualStart;
        } else {
          actualDeleteCount = Math.min(
            Math.max(toIntegerOrInfinity(deleteCount), 0),
            len - actualStart,
          );
        }

        const newLen = len - actualDeleteCount + items.length;
        const result = new Array(newLen);
        let r = 0;

        // Copy elements before start
        for (let i = 0; i < actualStart; i++) {
          result[r++] = o[i];
        }

        // Insert new items
        for (let i = 0; i < items.length; i++) {
          result[r++] = items[i];
        }

        // Copy remaining elements after deleted section
        for (let i = actualStart + actualDeleteCount; i < len; i++) {
          result[r++] = o[i];
        }

        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Array.fromAsync (ES2024)
  // Creates a new Array from an async iterable or iterable/array-like.
  // --------------------------------------------------------------------------
  if (typeof Array.fromAsync !== 'function') {
    Object.defineProperty(Array, 'fromAsync', {
      value: async function fromAsync(
        arrayLike: any,
        mapFn?: (value: any, index: number) => any,
        thisArg?: any,
      ): Promise<any[]> {
        if (mapFn !== undefined && typeof mapFn !== 'function') {
          throw new TypeError('mapFn must be a function');
        }

        const result: any[] = [];
        let index = 0;

        // Try async iterator first
        if (arrayLike != null && typeof arrayLike[Symbol.asyncIterator] === 'function') {
          const iterator = arrayLike[Symbol.asyncIterator]();
          let shouldCloseIterator = false;

          try {
            while (true) {
              const step = await iterator.next();
              if (step.done) {
                return result;
              }

              // Keep the iterator closable while mapping or pushing the current
              // item so abrupt failures mirror for-await cleanup closely enough
              // for our runtime.
              shouldCloseIterator = true;
              const value = mapFn ? await mapFn.call(thisArg, step.value, index) : step.value;
              result.push(value);
              index++;
              shouldCloseIterator = false;
            }
          } catch (error) {
            if (shouldCloseIterator && typeof iterator.return === 'function') {
              try {
                await iterator.return();
              } catch {
                // Preserve the original failure from the mapper or consumer.
              }
            }
            throw error;
          }
        }

        // Try sync iterator
        if (arrayLike != null && typeof arrayLike[Symbol.iterator] === 'function') {
          for (const item of arrayLike) {
            const awaited = await item;
            const value = mapFn ? await mapFn.call(thisArg, awaited, index) : awaited;
            result.push(value);
            index++;
          }
          return result;
        }

        // Array-like object
        const len = (arrayLike && arrayLike.length) >>> 0;
        for (let i = 0; i < len; i++) {
          const awaited = await arrayLike[i];
          const value = mapFn ? await mapFn.call(thisArg, awaited, i) : awaited;
          result.push(value);
        }
        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
