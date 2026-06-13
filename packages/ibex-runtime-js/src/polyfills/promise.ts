// @ts-nocheck
/**
 * ES2024 Promise.withResolvers polyfill for Hermes engine
 *
 * - Promise.withResolvers()
 */

export function installPromisePolyfills(): void {
  // --------------------------------------------------------------------------
  // Promise.withResolvers (ES2024)
  // Returns an object with { promise, resolve, reject }.
  // Equivalent to:
  //   let resolve, reject;
  //   const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  //   return { promise, resolve, reject };
  // --------------------------------------------------------------------------
  if (typeof Promise.withResolvers !== 'function') {
    Object.defineProperty(Promise, 'withResolvers', {
      value: function withResolvers<T>(): {
        promise: Promise<T>;
        resolve: (value: T | PromiseLike<T>) => void;
        reject: (reason?: any) => void;
      } {
        let resolve!: (value: T | PromiseLike<T>) => void;
        let reject!: (reason?: any) => void;
        const promise = new Promise<T>((res, rej) => {
          resolve = res;
          reject = rej;
        });
        return { promise, resolve, reject };
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
