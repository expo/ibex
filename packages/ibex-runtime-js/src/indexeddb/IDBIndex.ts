/**
 * IDBIndex - IndexedDB Index
 *
 * Provides access to a subset of data in an object store,
 * with records sorted by the index key rather than the primary key.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBIndex
 */

import { IDBRequest } from './IDBRequest';
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
   *
   * Index reads are backed by the store's companion index-key table: filtering,
   * index-key ordering (primary key as tiebreak) and LIMIT push into SQL, so an
   * index query no longer scans + deserializes the whole store in JS. multiEntry
   * and unique are maintained on the write path. (ENG-23016)
   */
  get(query: any): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        const values = this._objectStore._indexGetValues(
          this.name,
          this._objectStore._queryRange(query),
          1,
        );
        request._resolve(values.length > 0 ? values[0] : undefined);
      } catch (e: any) {
        request._reject(e);
      }
    });
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
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        const keys = this._objectStore._indexGetKeys(
          this.name,
          this._objectStore._queryRange(query),
          1,
        );
        request._resolve(keys.length > 0 ? keys[0] : undefined);
      } catch (e: any) {
        request._reject(e);
      }
    });
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
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        // count of 0 (or absent) means "all" per the retrieve-multiple algorithm;
        // only a positive count becomes a SQL LIMIT. (ENG-23026)
        const values = this._objectStore._indexGetValues(
          this.name,
          this._objectStore._queryRange(query),
          count !== undefined && count > 0 ? count : undefined,
        );
        request._resolve(values);
      } catch (e: any) {
        request._reject(e);
      }
    });
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
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        // count of 0 (or absent) means "all" per the retrieve-multiple algorithm;
        // only a positive count becomes a SQL LIMIT. (ENG-23026)
        const keys = this._objectStore._indexGetKeys(
          this.name,
          this._objectStore._queryRange(query),
          count !== undefined && count > 0 ? count : undefined,
        );
        request._resolve(keys);
      } catch (e: any) {
        request._reject(e);
      }
    });
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
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        // COUNT(*) over the companion index table — no rows materialized in JS.
        request._resolve(
          this._objectStore._indexCount(this.name, this._objectStore._queryRange(query)),
        );
      } catch (e: any) {
        request._reject(e);
      }
    });
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
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        const records = this._objectStore._indexRecords(
          this.name,
          this._objectStore._queryRange(query),
        );
        if (records.length === 0) {
          request._resolve(null);
        } else {
          // Index keys are not unique, so the cursor re-orders for its direction
          // and de-dupes for the *unique variants (records arrive in ascending
          // index-key order from SQL).
          const cursor = new IDBCursorWithValue(this, direction ?? 'next', records, request);
          request._resolve(cursor);
        }
      } catch (e: any) {
        request._reject(e);
      }
    });
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
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        const records = this._objectStore._indexRecords(
          this.name,
          this._objectStore._queryRange(query),
        );
        if (records.length === 0) {
          request._resolve(null);
        } else {
          // A key cursor exposes only key/primaryKey and never a value: yield a
          // plain IDBCursor (not IDBCursorWithValue) and drop the values. (ENG-23026)
          const keyRecords = records.map(r => ({ key: r.key, primaryKey: r.primaryKey, value: undefined }));
          const cursor = new IDBCursor(this, direction ?? 'next', keyRecords, request);
          request._resolve(cursor);
        }
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
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
