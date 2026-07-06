/**
 * IDBCursor - IndexedDB Cursor
 *
 * Iterates over records in an object store or index.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBCursor
 */

import { IDBRequest } from './IDBRequest';
import { compareKeys } from './IDBKeyRange';
import { encodeOrderedKey } from './serialization';

export type IDBCursorDirection = 'next' | 'nextunique' | 'prev' | 'prevunique';

/** Default batch size for streaming object-store cursors. (ENG-23016) */
export const IDB_CURSOR_BATCH = 128;

/**
 * A bounded-memory row source for a streaming cursor: pages rows in direction
 * order via keyset pagination over the unique `keyenc` column, so the cursor
 * holds at most one batch at a time rather than the whole matching set.
 * (ENG-23016)
 */
export interface CursorStream {
  /**
   * Fetch the next batch. `after` is the exclusive keyenc bookmark of the last
   * row already consumed (null to start); `target` is an inclusive keyenc floor
   * used by continue(key) to re-seek. Rows come back in the cursor's direction.
   */
  fetch(after: string | null, target: string | null): Array<{ key: any; primaryKey: any; value: any; keyenc: string }>;
  batchSize: number;
}

export class IDBCursor {
  private _source: any;
  private _direction: IDBCursorDirection;
  private _records: Array<{ key: any; primaryKey: any; value: any; keyenc?: string }>;
  private _position: number;
  private _request: IDBRequest;
  private _gotValue: boolean = false;
  /**
   * @internal - When set, the cursor pages its rows lazily from SQL instead of
   * holding the whole matching set; `_records` is then just the current batch
   * and `_bookmark` is the keyenc of its last row. (ENG-23016)
   */
  private _stream: CursorStream | null = null;
  private _bookmark: string | null = null;

  constructor(
    source: any,
    direction: IDBCursorDirection,
    records: Array<{ key: any; primaryKey: any; value: any }>,
    request: IDBRequest,
    presorted: boolean = false,
    stream: CursorStream | null = null,
  ) {
    this._source = source;
    this._direction = direction;
    this._request = request;

    if (stream) {
      // Streaming (bounded-memory) mode: hold only the first batch; continue()/
      // advance() page in subsequent batches on demand. (ENG-23016)
      this._stream = stream;
      const first = stream.fetch(null, null);
      this._records = first;
      this._bookmark = first.length ? (first[first.length - 1] as any).keyenc : null;
    } else if (presorted) {
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
    if (this._stream) {
      this._streamContinue(key);
      return;
    }
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

    this._resolvePosition();
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
    if (this._stream) {
      // Page across batches until the target position lands inside a batch or
      // the stream is exhausted. (ENG-23016)
      while (this._position >= this._records.length) {
        const overflow = this._position - this._records.length;
        const batch = this._stream.fetch(this._bookmark, null);
        if (batch.length === 0) {
          this._records = [];
          this._position = 0;
          break;
        }
        this._records = batch;
        this._bookmark = (batch[batch.length - 1] as any).keyenc;
        this._position = overflow;
      }
    }
    this._resolvePosition();
  }

  /**
   * @internal - continue() for a streaming cursor: page in the next batch (or
   * re-seek to `key`) via keyset pagination instead of walking an in-memory
   * array. (ENG-23016)
   */
  private _streamContinue(key?: any): void {
    if (key !== undefined) {
      // Re-seek: strictly after the current row and at/after the target key.
      const cur = this._records[this._position] as any;
      const after = cur ? cur.keyenc : this._bookmark;
      this._loadBatch(this._stream!.fetch(after, encodeOrderedKey(key)));
    } else {
      this._position++;
      if (this._position >= this._records.length) {
        this._loadBatch(this._stream!.fetch(this._bookmark, null));
      }
    }
    this._resolvePosition();
  }

  /** @internal - Replace the current batch (from a fresh fetch) and reset position. */
  private _loadBatch(batch: Array<{ key: any; primaryKey: any; value: any; keyenc?: string }>): void {
    this._records = batch;
    this._position = 0;
    if (batch.length > 0) this._bookmark = (batch[batch.length - 1] as any).keyenc;
  }

  /** @internal - Resolve the bound request with the cursor (more) or null (done). */
  private _resolvePosition(): void {
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
    store._transaction._assertWritable(); // ReadOnlyError on readonly txns (ENG-23117)
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
    store._transaction._assertWritable(); // ReadOnlyError on readonly txns (ENG-23117)
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
    stream: CursorStream | null = null,
  ) {
    super(source, direction, records, request, presorted, stream);
    this._valueRecords = (this as any)._records;
  }

  get value(): any {
    const pos = (this as any)._position;
    const records = (this as any)._records;
    if (pos >= records.length) return undefined;
    return records[pos].value;
  }
}
