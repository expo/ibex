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
import { IDBKeyRange, isValidKey } from './IDBKeyRange';
import { DOMException } from './utils';

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
    // Spec: get() requires a key or key range; undefined/invalid keys are a
    // DataError. Previously undefined fell through to the "whole store" range
    // and returned an arbitrary first record — e.g. index.get(user.email)
    // with an accidentally-undefined email returned the wrong user.
    // (ENG-23134)
    if (!(query instanceof IDBKeyRange) && !isValidKey(query)) {
      throw new DOMException('The parameter is not a valid key.', 'DataError');
    }
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
    // Spec: DataError for undefined/invalid keys (see get()). (ENG-23134)
    if (!(query instanceof IDBKeyRange) && !isValidKey(query)) {
      throw new DOMException('The parameter is not a valid key.', 'DataError');
    }
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
   *
   * Streams in bounded batches over the companion index-key table (composite
   * (keyenc, pkenc) keyset pagination; GROUP BY for the *unique directions),
   * re-querying live data per batch — mutations made mid-iteration inside the
   * same transaction are observed, matching store-cursor semantics, instead
   * of iterating a stale materialized snapshot. (ENG-23134)
   */
  openCursor(query?: any, direction?: IDBCursorDirection): IDBRequest {
    this._objectStore._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._objectStore._transaction;
    this._objectStore._transaction._enqueueOp(request, () => {
      try {
        const dir = direction ?? 'next';
        const stream = this._objectStore._indexCursorStreamer(
          this.name,
          this._objectStore._queryRange(query),
          dir,
          true,
        );
        const first = stream.fetch(null, null);
        if (first.length === 0) {
          request._resolve(null);
        } else {
          const cursor = new IDBCursorWithValue(this, dir, first, request, stream);
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
        // A key cursor exposes only key/primaryKey and never a value: stream
        // the index table alone (no store JOIN, no value deserialization) and
        // yield a plain IDBCursor. (ENG-23026 / ENG-23134)
        const dir = direction ?? 'next';
        const stream = this._objectStore._indexCursorStreamer(
          this.name,
          this._objectStore._queryRange(query),
          dir,
          false,
        );
        const first = stream.fetch(null, null);
        if (first.length === 0) {
          request._resolve(null);
        } else {
          const cursor = new IDBCursor(this, dir, first, request, stream);
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
