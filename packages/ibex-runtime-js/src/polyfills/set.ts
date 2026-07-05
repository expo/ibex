// @ts-nocheck
/**
 * ES2025 Set methods polyfills for Hermes engine
 *
 * - Set.prototype.union()
 * - Set.prototype.intersection()
 * - Set.prototype.difference()
 * - Set.prototype.symmetricDifference()
 * - Set.prototype.isSubsetOf()
 * - Set.prototype.isSupersetOf()
 * - Set.prototype.isDisjointFrom()
 */

/**
 * Helper: get the size of a Set-like object.
 */
function getSetLikeSize(other: any): number {
  if (typeof other.size === 'number') return other.size;
  if (typeof other.size === 'function') return other.size();
  throw new TypeError('Set-like object must have a size property');
}

/**
 * Helper: ensure a Set-like has the minimum required interface.
 *
 * Per GetSetRecord, a Set-like must expose a numeric `size`, a callable `has`,
 * AND a callable `keys`. The `keys` method was previously never validated.
 * (ENG-22984)
 */
function requireSetLike(other: any): void {
  if (other == null || typeof other !== 'object') {
    throw new TypeError('The argument must be a Set-like object');
  }
  if (typeof other.has !== 'function') {
    throw new TypeError('Set-like object must have a has method');
  }
  if (typeof other.keys !== 'function') {
    throw new TypeError('Set-like object must have a keys method');
  }
}

/**
 * Iterate a Set-like's elements via its `keys()` method (the [[Keys]] slot of
 * the Set Record), NOT via `Symbol.iterator`/`forEach`. These differ for the
 * canonical set-like — a Map — whose default iterator yields `[key, value]`
 * pairs while `keys()` yields the bare keys the set operations must consume.
 * The callback may return `false` to stop iteration early (the keys iterator is
 * then closed). (ENG-22984)
 */
function forEachSetLikeKey(other: any, callback: (value: any) => boolean | void): void {
  const iterator = other.keys();
  if (iterator == null || typeof iterator.next !== 'function') {
    throw new TypeError('Set-like keys() method must return an iterator');
  }
  while (true) {
    const step = iterator.next();
    if (step == null || step.done) break;
    if (callback(step.value) === false) {
      if (typeof iterator.return === 'function') {
        try {
          iterator.return();
        } catch {
          /* ignore errors from closing the iterator */
        }
      }
      break;
    }
  }
}

export function installSetPolyfills(): void {
  // --------------------------------------------------------------------------
  // Set.prototype.union
  // Returns a new Set containing all elements from both this and other.
  // --------------------------------------------------------------------------
  if (typeof Set.prototype.union !== 'function') {
    Object.defineProperty(Set.prototype, 'union', {
      value: function union<T>(this: Set<T>, other: Set<T>): Set<T> {
        requireSetLike(other);
        const result = new Set<T>(this);
        forEachSetLikeKey(other, (value: T) => {
          result.add(value);
        });
        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Set.prototype.intersection
  // Returns a new Set containing elements present in both this and other.
  // --------------------------------------------------------------------------
  if (typeof Set.prototype.intersection !== 'function') {
    Object.defineProperty(Set.prototype, 'intersection', {
      value: function intersection<T>(this: Set<T>, other: Set<T>): Set<T> {
        requireSetLike(other);
        const result = new Set<T>();
        const otherSize = getSetLikeSize(other);

        // Iterate the smaller set for performance
        if (this.size <= otherSize) {
          for (const value of this) {
            if (other.has(value)) {
              result.add(value);
            }
          }
        } else {
          forEachSetLikeKey(other, (value: T) => {
            if (this.has(value)) {
              result.add(value);
            }
          });
        }

        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Set.prototype.difference
  // Returns a new Set containing elements in this but not in other.
  // --------------------------------------------------------------------------
  if (typeof Set.prototype.difference !== 'function') {
    Object.defineProperty(Set.prototype, 'difference', {
      value: function difference<T>(this: Set<T>, other: Set<T>): Set<T> {
        requireSetLike(other);
        const result = new Set<T>();
        for (const value of this) {
          if (!other.has(value)) {
            result.add(value);
          }
        }
        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Set.prototype.symmetricDifference
  // Returns a new Set containing elements in either this or other, but not both.
  // --------------------------------------------------------------------------
  if (typeof Set.prototype.symmetricDifference !== 'function') {
    Object.defineProperty(Set.prototype, 'symmetricDifference', {
      value: function symmetricDifference<T>(this: Set<T>, other: Set<T>): Set<T> {
        requireSetLike(other);
        const result = new Set<T>(this);
        // Membership is decided against the original `this` (not the evolving
        // result) so duplicate keys from a set-like toggle correctly.
        forEachSetLikeKey(other, (value: T) => {
          if (this.has(value)) {
            result.delete(value);
          } else {
            result.add(value);
          }
        });
        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Set.prototype.isSubsetOf
  // Returns true if every element of this is in other.
  // --------------------------------------------------------------------------
  if (typeof Set.prototype.isSubsetOf !== 'function') {
    Object.defineProperty(Set.prototype, 'isSubsetOf', {
      value: function isSubsetOf<T>(this: Set<T>, other: Set<T>): boolean {
        requireSetLike(other);
        const otherSize = getSetLikeSize(other);
        if (this.size > otherSize) return false;
        for (const value of this) {
          if (!other.has(value)) return false;
        }
        return true;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Set.prototype.isSupersetOf
  // Returns true if every element of other is in this.
  // --------------------------------------------------------------------------
  if (typeof Set.prototype.isSupersetOf !== 'function') {
    Object.defineProperty(Set.prototype, 'isSupersetOf', {
      value: function isSupersetOf<T>(this: Set<T>, other: Set<T>): boolean {
        requireSetLike(other);
        const otherSize = getSetLikeSize(other);
        if (this.size < otherSize) return false;
        let isSuperset = true;
        forEachSetLikeKey(other, (value: T) => {
          if (!this.has(value)) {
            isSuperset = false;
            return false; // stop iterating
          }
          return true;
        });
        return isSuperset;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Set.prototype.isDisjointFrom
  // Returns true if this and other have no elements in common.
  // --------------------------------------------------------------------------
  if (typeof Set.prototype.isDisjointFrom !== 'function') {
    Object.defineProperty(Set.prototype, 'isDisjointFrom', {
      value: function isDisjointFrom<T>(this: Set<T>, other: Set<T>): boolean {
        requireSetLike(other);
        const otherSize = getSetLikeSize(other);

        // Iterate the smaller set
        if (this.size <= otherSize) {
          for (const value of this) {
            if (other.has(value)) return false;
          }
        } else {
          let disjoint = true;
          forEachSetLikeKey(other, (value: T) => {
            if (this.has(value)) {
              disjoint = false;
              return false; // stop iterating
            }
            return true;
          });
          return disjoint;
        }
        return true;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
