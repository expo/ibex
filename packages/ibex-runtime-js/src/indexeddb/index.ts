// @ts-nocheck
/**
 * IndexedDB implementation for the Exact runtime
 *
 * Provides a server-side IndexedDB API backed by exact:sqlite.
 * Many npm packages use IndexedDB for caching/storage, and this
 * implementation enables those packages to work in the Exact runtime.
 *
 * @example
 * ```typescript
 * const request = indexedDB.open('myDatabase', 1);
 * request.onupgradeneeded = (event) => {
 *   const db = event.target.result;
 *   db.createObjectStore('users', { keyPath: 'id', autoIncrement: true });
 * };
 * request.onsuccess = (event) => {
 *   const db = event.target.result;
 *   const txn = db.transaction('users', 'readwrite');
 *   const store = txn.objectStore('users');
 *   store.put({ name: 'Alice' });
 * };
 * ```
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API
 */

export { IDBFactory, type SQLiteDatabaseProvider } from './IDBFactory';
export { IDBDatabase } from './IDBDatabase';
export { IDBTransaction, type IDBTransactionMode } from './IDBTransaction';
export { IDBObjectStore, type IDBObjectStoreParameters } from './IDBObjectStore';
export { IDBIndex, type IDBIndexParameters } from './IDBIndex';
export { IDBRequest, IDBOpenDBRequest } from './IDBRequest';
export { IDBKeyRange, compareKeys } from './IDBKeyRange';
export { IDBCursor, IDBCursorWithValue, type IDBCursorDirection } from './IDBCursor';
