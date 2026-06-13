/**
 * Shared utilities for the IndexedDB implementation.
 *
 * Consolidates DOMException and helper functions to avoid
 * duplicate definitions across modules and enable cross-module
 * instanceof checks.
 */

/**
 * DOMException polyfill.
 *
 * Uses globalThis.DOMException when available (e.g. if the runtime bootstrap
 * has already installed one) and falls back to a simple Error subclass.
 */
export const DOMException: {
  new (message: string, name: string): Error & { code: number; name: string };
} = (() => {
  if (typeof globalThis !== 'undefined' && (globalThis as any).DOMException) {
    return (globalThis as any).DOMException;
  }
  // Fallback polyfill
  class DOMExceptionPolyfill extends Error {
    readonly code: number;
    constructor(message: string, name: string) {
      super(message);
      this.name = name;
      this.code = 0;
    }
  }
  return DOMExceptionPolyfill as any;
})();

/**
 * Create a DOMStringList-like object from a string array.
 *
 * The returned value extends Array<string> with `.contains()` and `.item()`
 * methods, matching the DOMStringList interface that IndexedDB consumers
 * expect.
 */
export function makeDOMStringList(names: string[]): string[] & { contains(name: string): boolean; item(index: number): string | null } {
  const list = [...names] as string[] & { contains(name: string): boolean; item(index: number): string | null };
  list.contains = (name: string) => list.includes(name);
  list.item = (index: number) => list[index] ?? null;
  return list;
}

/**
 * Sanitize a name for use as a SQL table/column identifier.
 */
export function sanitizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_');
}
