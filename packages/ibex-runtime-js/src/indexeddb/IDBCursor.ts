/**
 * IDBCursor - IndexedDB Cursor
 *
 * Iterates over records in an object store or index.
 *
 * All cursors stream: they page rows in bounded batches via keyset pagination
 * (object-store cursors bookmark on the unique `keyenc`; index cursors on the
 * composite `(keyenc, pkenc)` — see the streamer builders in IDBObjectStore),
 * re-querying live data each batch instead of iterating a materialized
 * snapshot. (ENG-23016 / ENG-23134)
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBCursor
 */

import { IDBRequest } from './IDBRequest';
import { compareKeys, isValidKey } from './IDBKeyRange';
import { encodeOrderedKey } from './serialization';
import { DOMException } from './utils';

export type IDBCursorDirection = 'next' | 'nextunique' | 'prev' | 'prevunique';

/** Default batch size for streaming cursors. (ENG-23016) */
export const IDB_CURSOR_BATCH = 128;

/**
 * A bounded-memory row source for a streaming cursor: pages rows in direction
 * order via keyset pagination, so the cursor holds at most one batch at a time
 * rather than the whole matching set. (ENG-23016)
 */
export interface CursorStream {
  /**
   * Fetch the next batch. `after` is the exclusive bookmark of the last row
   * already consumed (null to start; opaque — produced by this stream's own
   * rows); `target` is an inclusive keyenc floor used by continue(key) to
   * re-seek. Rows come back in the cursor's direction.
   */
  fetch(after: any, target: string | null): Array<{ key: any; primaryKey: any; value: any; bookmark: any }>;
  batchSize: number;
}

export class IDBCursor {
  private _source: any;
  private _direction: IDBCursorDirection;
  /** @internal - The current batch of rows (a bounded window, not the full set). */
  private _records: Array<{ key: any; primaryKey: any; value: any; bookmark?: any }>;
  private _position: number;
  private _request: IDBRequest;
  private _gotValue: boolean = false;
  /** @internal - Pages rows lazily from SQL; `_bookmark` marks the last row of the current batch. */
  private _stream: CursorStream;
  private _bookmark: any = null;

  constructor(
    source: any,
    direction: IDBCursorDirection,
    firstBatch: Array<{ key: any; primaryKey: any; value: any; bookmark?: any }>,
    request: IDBRequest,
    stream: CursorStream,
  ) {
    this._source = source;
    this._direction = direction;
    this._request = request;
    this._stream = stream;
    // The opener already fetched the first batch (to distinguish "no match" →
    // null result from a live cursor); reuse it rather than re-querying.
    this._records = firstBatch;
    this._bookmark = firstBatch.length ? firstBatch[firstBatch.length - 1].bookmark : null;
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
    // Spec: InvalidStateError once the cursor has iterated past its end (got
    // value flag unset) — previously continue() re-fetched from the last
    // bookmark and could "resurrect" an exhausted cursor when rows were
    // inserted behind it. (ENG-23446)
    this._assertGotValue();
    if (key !== undefined) {
      // Spec: DataError for an invalid key, and for a key at or behind the
      // cursor's position (previously this silently acted like continue()).
      // (ENG-23134)
      if (!isValidKey(key)) {
        throw new DOMException('The parameter is not a valid key.', 'DataError');
      }
      const current = this.key;
      if (current !== undefined) {
        const cmp = compareKeys(key, current);
        const behind = this._direction === 'prev' || this._direction === 'prevunique'
          ? cmp >= 0
          : cmp <= 0;
        if (behind) {
          throw new DOMException(
            'The parameter is not after (in iteration order) this cursor\'s position.',
            'DataError',
          );
        }
      }
    }
    this._streamContinue(key);
  }

  /**
   * Advances the cursor by a given number of positions.
   */
  advance(count: number): void {
    // Spec: TypeError for a missing/zero/non-integer count. Previously
    // advance() with no argument slid `_position` to NaN and silently ended
    // the cursor. (ENG-23134)
    if (typeof count !== 'number' || !Number.isInteger(count) || count <= 0) {
      throw new TypeError('count must be a positive integer');
    }
    const tx = this._request.transaction;
    if (tx && tx._assertActive) tx._assertActive();
    // Spec: InvalidStateError once the cursor is past its end. (ENG-23446)
    this._assertGotValue();
    this._position += count;
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
      this._bookmark = batch[batch.length - 1].bookmark;
      this._position = overflow;
    }
    this._resolvePosition();
  }

  /** @internal - Throw InvalidStateError when the cursor is not on a record. */
  private _assertGotValue(): void {
    if (!this._gotValue) {
      throw new DOMException(
        'The cursor is being iterated or has iterated past its end.',
        'InvalidStateError',
      );
    }
  }

  /**
   * @internal - continue() for a streaming cursor: page in the next batch (or
   * re-seek to `key`) via keyset pagination instead of walking an in-memory
   * array. (ENG-23016)
   */
  private _streamContinue(key?: any): void {
    if (key !== undefined) {
      // Re-seek: strictly after the current row and at/after the target key.
      const cur = this._records[this._position];
      const after = cur ? cur.bookmark : this._bookmark;
      this._loadBatch(this._stream.fetch(after, encodeOrderedKey(key)));
    } else {
      this._position++;
      if (this._position >= this._records.length) {
        this._loadBatch(this._stream.fetch(this._bookmark, null));
      }
    }
    this._resolvePosition();
  }

  /** @internal - Replace the current batch (from a fresh fetch) and reset position. */
  private _loadBatch(batch: Array<{ key: any; primaryKey: any; value: any; bookmark?: any }>): void {
    this._records = batch;
    this._position = 0;
    if (batch.length > 0) this._bookmark = batch[batch.length - 1].bookmark;
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
    // Spec: key cursors (openKeyCursor) carry no value and cannot update;
    // a cursor that is not currently on a record cannot either. (ENG-23134)
    if (!(this instanceof IDBCursorWithValue)) {
      throw new DOMException('The cursor is a key cursor.', 'InvalidStateError');
    }
    if (!this._gotValue || this._position >= this._records.length) {
      throw new DOMException('The cursor is not pointing to a record.', 'InvalidStateError');
    }
    const record = this._records[this._position];
    // Spec: on an in-line-key store the new value's key must equal this
    // record's primary key (previously any mismatch silently re-keyed the
    // record). (ENG-23134)
    if (store.keyPath !== null) {
      const inlineKey = store._extractInlineKey(value);
      if (inlineKey === undefined || !isValidKey(inlineKey) || compareKeys(inlineKey, record.primaryKey) !== 0) {
        throw new DOMException(
          "The effective object store uses in-line keys and the value's key does not match the cursor's position.",
          'DataError',
        );
      }
    }
    const request = new IDBRequest();
    request.transaction = store._transaction;
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
    // Spec: key cursors cannot delete, and neither can a cursor not currently
    // on a record. (ENG-23134)
    if (!(this instanceof IDBCursorWithValue)) {
      throw new DOMException('The cursor is a key cursor.', 'InvalidStateError');
    }
    if (!this._gotValue || this._position >= this._records.length) {
      throw new DOMException('The cursor is not pointing to a record.', 'InvalidStateError');
    }
    const record = this._records[this._position];
    const request = new IDBRequest();
    request.transaction = store._transaction;
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
  constructor(
    source: any,
    direction: IDBCursorDirection,
    firstBatch: Array<{ key: any; primaryKey: any; value: any; bookmark?: any }>,
    request: IDBRequest,
    stream: CursorStream,
  ) {
    super(source, direction, firstBatch, request, stream);
  }

  get value(): any {
    const pos = (this as any)._position;
    const records = (this as any)._records;
    if (pos >= records.length) return undefined;
    return records[pos].value;
  }
}
