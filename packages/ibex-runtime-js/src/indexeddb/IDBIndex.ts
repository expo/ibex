/**
 * IDBIndex - IndexedDB Index
 *
 * Provides access to a subset of data in an object store,
 * with records sorted by the index key rather than the primary key.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBIndex
 */

import { IDBRequest } from './IDBRequest';
import { IDBKeyRange, compareKeys } from './IDBKeyRange';
import { IDBCursor, IDBCursorWithValue, type IDBCursorDirection } from './IDBCursor';

export interface IDBIndexParameters {
  unique?: boolean;
  multiEntry?: boolean;
}

export class IDBIndex {
  readonly name: string;
  readonly keyPath: string | string[];
  readonly unique: boolean;
  readonly multiEntry: boolean;
  /** @internal */
  _objectStore: any;

  constructor(
    name: string,
    keyPath: string | string[],
    options: IDBIndexParameters,
    objectStore: any,
  ) {
    this.name = name;
    this.keyPath = keyPath;
    this.unique = options.unique ?? false;
    this.multiEntry = options.multiEntry ?? false;
    this._objectStore = objectStore;
  }

  get objectStore(): any {
    return this._objectStore;
  }

  /**
   * Retrieve the first record matching a key or key range from this index.
   */
  get(query: any): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    try {
      const records = this._getMatchingRecords(query);
      request._resolve(records.length > 0 ? records[0].value : undefined);
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Retrieve the key of the first record matching from this index.
   */
  getKey(query: any): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    try {
      const records = this._getMatchingRecords(query);
      request._resolve(records.length > 0 ? records[0].primaryKey : undefined);
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Retrieve all records matching from this index.
   */
  getAll(query?: any, count?: number): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    try {
      let records = this._getMatchingRecords(query);
      // count of 0 (or absent) means "all" per the retrieve-multiple algorithm;
      // only a positive count limits the result. (ENG-23026)
      if (count !== undefined && count > 0) {
        records = records.slice(0, count);
      }
      request._resolve(records.map(r => r.value));
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Retrieve all keys matching from this index.
   */
  getAllKeys(query?: any, count?: number): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    try {
      let records = this._getMatchingRecords(query);
      // count of 0 (or absent) means "all" per the retrieve-multiple algorithm;
      // only a positive count limits the result. (ENG-23026)
      if (count !== undefined && count > 0) {
        records = records.slice(0, count);
      }
      request._resolve(records.map(r => r.primaryKey));
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Count records matching a key or range in this index.
   */
  count(query?: any): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    try {
      const records = this._getMatchingRecords(query);
      request._resolve(records.length);
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Open a cursor over the index's records.
   */
  openCursor(query?: any, direction?: IDBCursorDirection): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    try {
      const records = this._getMatchingRecords(query);
      if (records.length === 0) {
        request._resolve(null);
      } else {
        const cursor = new IDBCursorWithValue(this, direction ?? 'next', records, request);
        request._resolve(cursor);
      }
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Open a key cursor over the index.
   */
  openKeyCursor(query?: any, direction?: IDBCursorDirection): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    try {
      const records = this._getMatchingRecords(query);
      if (records.length === 0) {
        request._resolve(null);
      } else {
        // A key cursor exposes only key/primaryKey and never a value: yield a
        // plain IDBCursor (not IDBCursorWithValue) and drop the deserialized
        // values so they aren't retained or surfaced. (ENG-23026)
        const keyRecords = records.map(r => ({ key: r.key, primaryKey: r.primaryKey, value: undefined }));
        const cursor = new IDBCursor(this, direction ?? 'next', keyRecords, request);
        request._resolve(cursor);
      }
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /** @internal - Get records that match a query via this index, in index-key order */
  _getMatchingRecords(query?: any): Array<{ key: any; primaryKey: any; value: any }> {
    const keyPath = this.keyPath;
    const allRecords = this._objectStore._getAllRecords();

    // Extract the index key from each record. A record whose value yields no key
    // at the index's key path is NOT represented in the index, so it is dropped
    // in EVERY branch — including the unbounded one, which previously leaked such
    // records into getAll/getAllKeys/count. (ENG-23026)
    const indexedRecords: Array<{ key: any; primaryKey: any; value: any }> = [];
    for (const r of allRecords) {
      const key = extractKeyPath(r.value, keyPath);
      if (key === undefined) continue;
      indexedRecords.push({ key, primaryKey: r.key, value: r.value });
    }

    // Index accessors must return records in index-key order, with the primary
    // key as the tiebreak — NOT the primary-key order _getAllRecords yields.
    // Only the index cursor used to re-sort; get/getKey/getAll/getAllKeys/count
    // silently returned primary-key order before this. (ENG-23026)
    indexedRecords.sort((a, b) => {
      const c = compareKeys(a.key, b.key);
      return c !== 0 ? c : compareKeys(a.primaryKey, b.primaryKey);
    });

    if (query === undefined || query === null) {
      return indexedRecords;
    }

    const range = query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
    return indexedRecords.filter((r: any) => range.includes(r.key));
  }
}

/**
 * Extract a value from an object using a key path.
 */
export function extractKeyPath(obj: any, keyPath: string | string[]): any {
  if (obj === null || obj === undefined) return undefined;

  if (Array.isArray(keyPath)) {
    return keyPath.map(kp => extractSingleKeyPath(obj, kp));
  }
  return extractSingleKeyPath(obj, keyPath);
}

function extractSingleKeyPath(obj: any, keyPath: string): any {
  const parts = keyPath.split('.');
  let current = obj;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    current = current[part];
  }
  return current;
}
