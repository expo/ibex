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
 * LEGACY name sanitizer. Folds every non-`[a-zA-Z0-9_]` character to `_`,
 * which is LOSSY: "user-data" and "user_data" (or, since SQLite identifiers
 * are ASCII case-insensitive, "Settings" and "settings") collapsed onto one
 * SQLite table while remaining distinct object stores — writes merged and
 * deleting one store dropped the other's data. Kept ONLY so the collision-free
 * encoding below can find (and rename) tables created by older builds; do not
 * use it for new table-name computations. (ENG-23134)
 */
export function sanitizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_');
}

/**
 * Collision-free SQL identifier encoding for object-store names. (ENG-23134)
 *
 * Two classes, chosen so the overwhelmingly common store names keep the exact
 * table names older builds created (no migration for them):
 *  - a name that is nonempty, all `[a-z0-9_]`, and does not end in `_enc`
 *    passes through unchanged (identical to what sanitizeName produced);
 *  - anything else (uppercase — case-insensitive in SQLite identifiers —
 *    punctuation, unicode, empty, or a lowercase name ending in `_enc`)
 *    becomes fixed-width hex of its code points plus an `_enc` suffix.
 * Injective: hex is fixed-width per code point, pass-through names never end
 * in `_enc`, and encoded names always do — so distinct store names can never
 * share a table. The output alphabet is `[a-z0-9_]`, safe to interpolate
 * inside a quoted SQL identifier.
 */
export function encodeIdentifier(name: string): string {
  if (/^[a-z0-9_]+$/.test(name) && !name.endsWith('_enc')) return name;
  let hex = '';
  for (const ch of name) {
    hex += ch.codePointAt(0)!.toString(16).padStart(6, '0');
  }
  return `${hex}_enc`;
}

/** The SQLite table backing an object store. (ENG-23134) */
export function storeTableName(name: string): string {
  return `idb_store_${encodeIdentifier(name)}`;
}

/** The companion index-key table for an object store. (ENG-23016 / ENG-23134) */
export function indexTableName(name: string): string {
  return `idb_index_${encodeIdentifier(name)}`;
}

/** Where an older (lossy-sanitizer) build would have put the store table. */
export function legacyStoreTableName(name: string): string {
  return `idb_store_${sanitizeName(name)}`;
}

/** Where an older (lossy-sanitizer) build would have put the index table. */
export function legacyIndexTableName(name: string): string {
  return `idb_index_${sanitizeName(name)}`;
}
