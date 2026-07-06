/**
 * IDBCursor - IndexedDB Cursor
 *
 * Iterates over records in an object store or index.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBCursor
 */

import { IDBRequest } from './IDBRequest';
import { compareKeys } from './IDBKeyRange';

export type IDBCursorDirection = 'next' | 'nextunique' | 'prev' | 'prevunique';

export class IDBCursor {
  private _source: any;
  private _direction: IDBCursorDirection;
  private _records: Array<{ key: any; primaryKey: any; value: any }>;
  private _position: number;
  private _request: IDBRequest;
  private _gotValue: boolean = false;

  constructor(
    source: any,
    direction: IDBCursorDirection,
    records: Array<{ key: any; primaryKey: any; value: any }>,
    request: IDBRequest,
    presorted: boolean = false,
  ) {
    this._source = source;
    this._direction = direction;
    this._request = request;

    if (presorted) {
      // The caller already ordered the rows by direction in SQL and guarantees
      // unique keys (object-store cursors), so no JS sort or dedup is needed —
      // this is what lets a ranged/unbounded object-store cursor avoid the
      // O(n log n) re-sort the old path always paid. (ENG-22999)
      this._records = records;
    } else {
      // Sort records based on direction
      const sorted = [...records];
      if (direction === 'prev' || direction === 'prevunique') {
        sorted.sort((a, b) => compareKeys(b.key, a.key));
      } else {
        sorted.sort((a, b) => compareKeys(a.key, b.key));
      }

      // For unique directions, deduplicate by key
      if (direction === 'nextunique' || direction === 'prevunique') {
        const seen = new Set<string>();
        this._records = sorted.filter(r => {
          const keyStr = JSON.stringify(r.key);
          if (seen.has(keyStr)) return false;
          seen.add(keyStr);
          return true;
        });
      } else {
        this._records = sorted;
      }
    }

    this._position = 0;
    this._gotValue = this._records.length > 0;
  }

  get source(): any {
    return this._source;
  }

  get direction(): IDBCursorDirection {
    return this._direction;
  }

  get key(): any {
    if (!this._gotValue || this._position >= this._records.length) return undefined;
    return this._records[this._position].key;
  }

  get primaryKey(): any {
    if (!this._gotValue || this._position >= this._records.length) return undefined;
    return this._records[this._position].primaryKey;
  }

  get request(): IDBRequest {
    return this._request;
  }

  /**
   * Advances the cursor to the next position.
   */
  continue(key?: any): void {
    const tx = this._request.transaction;
    if (tx && tx._assertActive) tx._assertActive();
    this._position++;
    if (key !== undefined) {
      // Skip to the first record with key >= given key (or <= for prev)
      while (this._position < this._records.length) {
        const cmp = compareKeys(this._records[this._position].key, key);
        if (this._direction === 'prev' || this._direction === 'prevunique') {
          if (cmp <= 0) break;
        } else {
          if (cmp >= 0) break;
        }
        this._position++;
      }
    }

    if (this._position < this._records.length) {
      this._gotValue = true;
      this._request._resolve(this as any);
    } else {
      this._gotValue = false;
      this._request._resolve(null as any);
    }
  }

  /**
   * Advances the cursor by a given number of positions.
   */
  advance(count: number): void {
    if (count <= 0) {
      throw new TypeError('count must be greater than 0');
    }
    const tx = this._request.transaction;
    if (tx && tx._assertActive) tx._assertActive();
    this._position += count;
    if (this._position < this._records.length) {
      this._gotValue = true;
      this._request._resolve(this as any);
    } else {
      this._gotValue = false;
      this._request._resolve(null as any);
    }
  }

  /** @internal - The object store backing this cursor's source. */
  private _store(): any {
    return this._source._objectStore || this._source;
  }

  /**
   * Updates the value at the current cursor position.
   */
  update(value: any): IDBRequest {
    const store = this._store();
    store._transaction._assertActive();
    const request = new IDBRequest();
    request.transaction = store._transaction;
    if (!this._gotValue || this._position >= this._records.length) {
      request._reject(new Error('Cursor is not pointing to a record'));
      return request;
    }
    const record = this._records[this._position];
    // Update via the source's object store
    try {
      store._putRecord(record.primaryKey, value);
      record.value = value;
      request._resolve(record.primaryKey);
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Deletes the record at the current cursor position.
   */
  delete(): IDBRequest {
    const store = this._store();
    store._transaction._assertActive();
    const request = new IDBRequest();
    request.transaction = store._transaction;
    if (!this._gotValue || this._position >= this._records.length) {
      request._reject(new Error('Cursor is not pointing to a record'));
      return request;
    }
    const record = this._records[this._position];
    try {
      store._deleteRecord(record.primaryKey);
      request._resolve(undefined);
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }
}

/**
 * IDBCursorWithValue extends IDBCursor with a value property.
 */
export class IDBCursorWithValue extends IDBCursor {
  private _valueRecords: Array<{ key: any; primaryKey: any; value: any }>;

  constructor(
    source: any,
    direction: IDBCursorDirection,
    records: Array<{ key: any; primaryKey: any; value: any }>,
    request: IDBRequest,
    presorted: boolean = false,
  ) {
    super(source, direction, records, request, presorted);
    this._valueRecords = (this as any)._records;
  }

  get value(): any {
    const pos = (this as any)._position;
    const records = (this as any)._records;
    if (pos >= records.length) return undefined;
    return records[pos].value;
  }
}
