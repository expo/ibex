// @ts-nocheck
/**
 * ES2024 Object.groupBy and Map.groupBy polyfills for Hermes engine
 *
 * - Object.groupBy()
 * - Map.groupBy()
 */

export function installGroupByPolyfills(): void {
  // --------------------------------------------------------------------------
  // Object.groupBy (ES2024)
  // Groups elements of an iterable by a callback's return value into a
  // null-prototype object.
  // --------------------------------------------------------------------------
  if (typeof Object.groupBy !== 'function') {
    Object.defineProperty(Object, 'groupBy', {
      value: function groupBy<T>(
        items: Iterable<T>,
        callbackFn: (element: T, index: number) => PropertyKey,
      ): Record<PropertyKey, T[]> {
        if (typeof callbackFn !== 'function') {
          throw new TypeError('callbackFn must be a function');
        }
        if (items == null) {
          throw new TypeError('items is null or undefined');
        }

        const result = Object.create(null) as Record<PropertyKey, T[]>;
        let index = 0;

        for (const item of items) {
          const key = callbackFn(item, index++);
          if (key in result) {
            result[key].push(item);
          } else {
            result[key] = [item];
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
  // Map.groupBy (ES2024)
  // Groups elements of an iterable by a callback's return value into a Map.
  // --------------------------------------------------------------------------
  if (typeof Map.groupBy !== 'function') {
    Object.defineProperty(Map, 'groupBy', {
      value: function groupBy<T, K>(
        items: Iterable<T>,
        callbackFn: (element: T, index: number) => K,
      ): Map<K, T[]> {
        if (typeof callbackFn !== 'function') {
          throw new TypeError('callbackFn must be a function');
        }
        if (items == null) {
          throw new TypeError('items is null or undefined');
        }

        const result = new Map<K, T[]>();
        let index = 0;

        for (const item of items) {
          const key = callbackFn(item, index++);
          const group = result.get(key);
          if (group !== undefined) {
            group.push(item);
          } else {
            result.set(key, [item]);
          }
        }

        return result;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
