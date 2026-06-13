/**
 * ES2025 Iterator Helpers polyfills for Hermes engine
 *
 * - Iterator.prototype.map()
 * - Iterator.prototype.filter()
 * - Iterator.prototype.take()
 * - Iterator.prototype.drop()
 * - Iterator.prototype.flatMap()
 * - Iterator.prototype.reduce()
 * - Iterator.prototype.toArray()
 * - Iterator.prototype.forEach()
 * - Iterator.prototype.some()
 * - Iterator.prototype.every()
 * - Iterator.prototype.find()
 * - Iterator.from()
 */

export function installIteratorPolyfills(): void {
  const g = globalThis as any;

  // We need the Iterator constructor. If it doesn't exist, create it.
  // Per the spec, Iterator is a global constructor with a prototype that
  // iterator helpers live on.
  let IteratorConstructor: any = g.Iterator;

  if (typeof IteratorConstructor !== 'function') {
    // Create the Iterator constructor
    IteratorConstructor = function Iterator(this: any) {
      if (new.target === IteratorConstructor) {
        throw new TypeError('Iterator is not directly constructible');
      }
    };

    IteratorConstructor.prototype = Object.create(null);
    Object.defineProperty(IteratorConstructor.prototype, Symbol.iterator, {
      value: function() { return this; },
      writable: true,
      enumerable: false,
      configurable: true,
    });
    Object.defineProperty(IteratorConstructor.prototype, 'constructor', {
      value: IteratorConstructor,
      writable: true,
      enumerable: false,
      configurable: true,
    });
    Object.defineProperty(IteratorConstructor.prototype, Symbol.toStringTag, {
      value: 'Iterator',
      writable: false,
      enumerable: false,
      configurable: true,
    });

    Object.defineProperty(g, 'Iterator', {
      value: IteratorConstructor,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  const IteratorProto = IteratorConstructor.prototype;

  /**
   * Helper to create a wrapper iterator that inherits from Iterator.prototype.
   */
  function createIteratorHelper(
    nextFn: () => IteratorResult<any>,
    returnFn?: () => IteratorResult<any>,
  ): any {
    const iter = Object.create(IteratorProto);
    Object.defineProperty(iter, 'next', {
      value: nextFn,
      writable: true,
      enumerable: false,
      configurable: true,
    });
    if (returnFn) {
      Object.defineProperty(iter, 'return', {
        value: returnFn,
        writable: true,
        enumerable: false,
        configurable: true,
      });
    }
    return iter;
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.map
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.map !== 'function') {
    Object.defineProperty(IteratorProto, 'map', {
      value: function map(this: any, mapper: (value: any, index: number) => any): any {
        if (typeof mapper !== 'function') {
          throw new TypeError('mapper must be a function');
        }
        const source = this;
        let index = 0;
        return createIteratorHelper(
          function next() {
            const result = source.next();
            if (result.done) return result;
            return { value: mapper(result.value, index++), done: false };
          },
          function returnFn() {
            if (typeof source.return === 'function') return source.return();
            return { value: undefined, done: true };
          },
        );
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.filter
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.filter !== 'function') {
    Object.defineProperty(IteratorProto, 'filter', {
      value: function filter(this: any, predicate: (value: any, index: number) => boolean): any {
        if (typeof predicate !== 'function') {
          throw new TypeError('predicate must be a function');
        }
        const source = this;
        let index = 0;
        return createIteratorHelper(
          function next(): IteratorResult<any> {
            while (true) {
              const result = source.next();
              if (result.done) return result;
              if (predicate(result.value, index++)) {
                return { value: result.value, done: false };
              }
            }
          },
          function returnFn() {
            if (typeof source.return === 'function') return source.return();
            return { value: undefined, done: true };
          },
        );
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.take
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.take !== 'function') {
    Object.defineProperty(IteratorProto, 'take', {
      value: function take(this: any, limit: number): any {
        const n = Number(limit);
        if (!Number.isInteger(n) || n < 0) {
          throw new RangeError('take argument must be a non-negative integer');
        }
        const source = this;
        let remaining = n;
        return createIteratorHelper(
          function next() {
            if (remaining <= 0) {
              return { value: undefined, done: true };
            }
            remaining--;
            const result = source.next();
            if (result.done) remaining = 0;
            return result;
          },
          function returnFn() {
            if (typeof source.return === 'function') return source.return();
            return { value: undefined, done: true };
          },
        );
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.drop
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.drop !== 'function') {
    Object.defineProperty(IteratorProto, 'drop', {
      value: function drop(this: any, count: number): any {
        const n = Number(count);
        if (!Number.isInteger(n) || n < 0) {
          throw new RangeError('drop argument must be a non-negative integer');
        }
        const source = this;
        let dropped = false;
        return createIteratorHelper(
          function next() {
            if (!dropped) {
              dropped = true;
              for (let i = 0; i < n; i++) {
                const result = source.next();
                if (result.done) return result;
              }
            }
            return source.next();
          },
          function returnFn() {
            if (typeof source.return === 'function') return source.return();
            return { value: undefined, done: true };
          },
        );
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.flatMap
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.flatMap !== 'function') {
    Object.defineProperty(IteratorProto, 'flatMap', {
      value: function flatMap(this: any, mapper: (value: any, index: number) => any): any {
        if (typeof mapper !== 'function') {
          throw new TypeError('mapper must be a function');
        }
        const source = this;
        let index = 0;
        let innerIterator: any = null;
        return createIteratorHelper(
          function next(): IteratorResult<any> {
            while (true) {
              if (innerIterator !== null) {
                const innerResult = innerIterator.next();
                if (!innerResult.done) {
                  return { value: innerResult.value, done: false };
                }
                innerIterator = null;
              }
              const result = source.next();
              if (result.done) return result;
              const mapped = mapper(result.value, index++);
              // Per TC39 spec, the result must be an object (GetIteratorFlattenable)
              if (mapped == null || typeof mapped !== 'object') {
                throw new TypeError(
                  'GetIteratorFlattenable expects its first argument to be an object',
                );
              }
              if (typeof mapped[Symbol.iterator] === 'function') {
                innerIterator = mapped[Symbol.iterator]();
              } else if (typeof mapped.next === 'function') {
                innerIterator = mapped;
              } else {
                throw new TypeError(
                  'GetIteratorFlattenable expects its first argument to be an object',
                );
              }
            }
          },
          function returnFn() {
            if (innerIterator && typeof innerIterator.return === 'function') {
              innerIterator.return();
            }
            if (typeof source.return === 'function') return source.return();
            return { value: undefined, done: true };
          },
        );
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.reduce
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.reduce !== 'function') {
    Object.defineProperty(IteratorProto, 'reduce', {
      value: function reduce(
        this: any,
        reducer: (accumulator: any, value: any, index: number) => any,
        ...args: any[]
      ): any {
        if (typeof reducer !== 'function') {
          throw new TypeError('reducer must be a function');
        }
        const source = this;
        let accumulator: any;
        let index = 0;

        if (args.length > 0) {
          accumulator = args[0];
        } else {
          const first = source.next();
          if (first.done) {
            throw new TypeError('Reduce of empty iterator with no initial value');
          }
          accumulator = first.value;
          index = 1;
        }

        while (true) {
          const result = source.next();
          if (result.done) break;
          accumulator = reducer(accumulator, result.value, index++);
        }

        return accumulator;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.toArray
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.toArray !== 'function') {
    Object.defineProperty(IteratorProto, 'toArray', {
      value: function toArray(this: any): any[] {
        const result: any[] = [];
        while (true) {
          const item = this.next();
          if (item.done) break;
          result.push(item.value);
        }
        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.forEach
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.forEach !== 'function') {
    Object.defineProperty(IteratorProto, 'forEach', {
      value: function forEach(this: any, fn: (value: any, index: number) => void): void {
        if (typeof fn !== 'function') {
          throw new TypeError('fn must be a function');
        }
        let index = 0;
        while (true) {
          const result = this.next();
          if (result.done) break;
          fn(result.value, index++);
        }
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.some
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.some !== 'function') {
    Object.defineProperty(IteratorProto, 'some', {
      value: function some(this: any, predicate: (value: any, index: number) => boolean): boolean {
        if (typeof predicate !== 'function') {
          throw new TypeError('predicate must be a function');
        }
        let index = 0;
        while (true) {
          const result = this.next();
          if (result.done) return false;
          if (predicate(result.value, index++)) return true;
        }
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.every
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.every !== 'function') {
    Object.defineProperty(IteratorProto, 'every', {
      value: function every(this: any, predicate: (value: any, index: number) => boolean): boolean {
        if (typeof predicate !== 'function') {
          throw new TypeError('predicate must be a function');
        }
        let index = 0;
        while (true) {
          const result = this.next();
          if (result.done) return true;
          if (!predicate(result.value, index++)) return false;
        }
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.prototype.find
  // --------------------------------------------------------------------------
  if (typeof IteratorProto.find !== 'function') {
    Object.defineProperty(IteratorProto, 'find', {
      value: function find(
        this: any,
        predicate: (value: any, index: number) => boolean,
      ): any | undefined {
        if (typeof predicate !== 'function') {
          throw new TypeError('predicate must be a function');
        }
        let index = 0;
        while (true) {
          const result = this.next();
          if (result.done) return undefined;
          if (predicate(result.value, index++)) return result.value;
        }
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // Iterator.from (static)
  // Wraps a value into an Iterator. Accepts iterables and iterator-like objects.
  // --------------------------------------------------------------------------
  if (typeof IteratorConstructor.from !== 'function') {
    Object.defineProperty(IteratorConstructor, 'from', {
      value: function from(value: any): any {
        if (value == null) {
          throw new TypeError('Iterator.from requires a non-null value');
        }

        // If it's already an Iterator instance, return as-is
        if (value instanceof IteratorConstructor) {
          return value;
        }

        let iterator: any;

        // Try [Symbol.iterator]
        if (typeof value[Symbol.iterator] === 'function') {
          iterator = value[Symbol.iterator]();
        } else if (typeof value.next === 'function') {
          // It's already an iterator-like (has .next())
          iterator = value;
        } else {
          throw new TypeError('Value is not iterable or iterator-like');
        }

        // If the iterator already inherits from Iterator.prototype, return it
        if (iterator instanceof IteratorConstructor) {
          return iterator;
        }

        // Wrap it in an Iterator.prototype-based object
        return createIteratorHelper(
          function next() {
            return iterator.next();
          },
          function returnFn() {
            if (typeof iterator.return === 'function') return iterator.return();
            return { value: undefined, done: true };
          },
        );
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
