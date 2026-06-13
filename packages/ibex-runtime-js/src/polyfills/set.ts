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
 */
function requireSetLike(other: any): void {
  if (other == null || typeof other !== 'object') {
    throw new TypeError('The argument must be a Set-like object');
  }
  if (typeof other.has !== 'function') {
    throw new TypeError('Set-like object must have a has method');
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
        if (typeof other[Symbol.iterator] === 'function') {
          for (const value of other) {
            result.add(value);
          }
        } else if (typeof other.forEach === 'function') {
          other.forEach((value: T) => result.add(value));
        } else {
          throw new TypeError('Set-like object must be iterable or have forEach');
        }
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
          if (typeof other[Symbol.iterator] === 'function') {
            for (const value of other) {
              if (this.has(value)) {
                result.add(value);
              }
            }
          } else if (typeof other.forEach === 'function') {
            other.forEach((value: T) => {
              if (this.has(value)) {
                result.add(value);
              }
            });
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
        if (typeof other[Symbol.iterator] === 'function') {
          for (const value of other) {
            if (result.has(value)) {
              result.delete(value);
            } else {
              result.add(value);
            }
          }
        } else if (typeof other.forEach === 'function') {
          other.forEach((value: T) => {
            if (result.has(value)) {
              result.delete(value);
            } else {
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
        if (typeof other[Symbol.iterator] === 'function') {
          for (const value of other) {
            if (!this.has(value)) return false;
          }
        } else if (typeof other.forEach === 'function') {
          let allPresent = true;
          other.forEach((value: T) => {
            if (!this.has(value)) allPresent = false;
          });
          return allPresent;
        }
        return true;
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
          if (typeof other[Symbol.iterator] === 'function') {
            for (const value of other) {
              if (this.has(value)) return false;
            }
          } else if (typeof other.forEach === 'function') {
            let disjoint = true;
            other.forEach((value: T) => {
              if (this.has(value)) disjoint = false;
            });
            return disjoint;
          }
        }
        return true;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
