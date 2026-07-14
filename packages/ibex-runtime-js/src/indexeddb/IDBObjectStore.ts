/**
 * IDBObjectStore - IndexedDB Object Store
 *
 * Represents an object store in the database. Backed by a SQLite table.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBObjectStore
 */

import { IDBRequest } from './IDBRequest';
import { IDBIndex, type IDBIndexParameters, extractKeyPath } from './IDBIndex';
import { IDBKeyRange, isValidKey } from './IDBKeyRange';
import { IDBCursor, IDBCursorWithValue, IDB_CURSOR_BATCH, type IDBCursorDirection, type CursorStream } from './IDBCursor';
import { serializeKey, deserializeKey, serializeValue, deserializeValue, encodeOrderedKey, canonicalizeKey } from './serialization';
import {
  DOMException,
  storeTableName,
  indexTableName,
  legacyStoreTableName,
  legacyIndexTableName,
} from './utils';

export interface IDBObjectStoreParameters {
  keyPath?: string | string[] | null;
  autoIncrement?: boolean;
}

export class IDBObjectStore {
  readonly name: string;
  readonly keyPath: string | string[] | null;
  readonly autoIncrement: boolean;

  /** @internal */
  _transaction: any;
  /** @internal */
  _db: any; // The SQLite-backed database reference
  /** @internal */
  _indexes: Map<string, IDBIndex> = new Map();
  /** @internal */
  _tableName: string;

  constructor(
    name: string,
    options: IDBObjectStoreParameters,
    transaction: any,
    db: any,
  ) {
    this.name = name;
    this.keyPath = options.keyPath ?? null;
    this.autoIncrement = options.autoIncrement ?? false;
    this._transaction = transaction;
    this._db = db;
    // Collision-free encoding — distinct store names can never share a table.
    // (ENG-23134)
    this._tableName = storeTableName(name);

    // Create/migrate the SQLite table if needed. Deferred into the
    // transaction's operation queue: it must not run while an EARLIER
    // transaction still holds the connection's BEGIN (that transaction's
    // rollback would undo our DDL). FIFO ordering guarantees it runs before
    // any of this transaction's data operations. (ENG-23117)
    this._transaction._enqueueOp(null, () => this._ensureTable());
  }

  get indexNames(): string[] {
    return Array.from(this._indexes.keys()).sort();
  }

  get transaction(): any {
    return this._transaction;
  }

  /**
   * Add a record to the store. Fails if a record with the same key exists.
   */
  add(value: any, key?: any): IDBRequest {
    this._transaction._assertActive();
    this._transaction._assertWritable();
    // Spec: an explicit key argument on an in-line-key (keyPath) store is a
    // DataError — previously it silently re-keyed the record. (ENG-23134)
    if (key !== undefined && this.keyPath !== null) {
      throw new DOMException(
        'The object store uses in-line keys and the key parameter was provided.',
        'DataError',
      );
    }
    // IndexedDB performs structured serialization during the method call, not
    // when the transaction queue eventually executes the request. This both
    // snapshots subsequent mutations and makes DataCloneError synchronous.
    const clonedValue = deserializeValue(serializeValue(value));
    const clonedKey = key === undefined ? undefined : deserializeKey(serializeKey(key));
    if (this.keyPath !== null) {
      const inlineKey = extractKeyPath(clonedValue, this.keyPath);
      if (inlineKey !== undefined && !isValidKey(inlineKey)) {
        throw new DOMException('The keyPath value is not a valid key.', 'DataError');
      }
    }
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        const { key: resolvedKey, value: storedValue } = this._resolveKeyAndValue(clonedValue, clonedKey);
        if (this._hasRecord(resolvedKey)) {
          throw new DOMException(
            `A record with key ${JSON.stringify(resolvedKey)} already exists`,
            'ConstraintError',
          );
        }
        this._putRecord(resolvedKey, storedValue);
        request._resolve(resolvedKey);
      } catch (e: any) {
        request._reject(e instanceof DOMException ? e : new DOMException(e.message, 'DataError'));
      }
    });
    return request;
  }

  /**
   * Add or update a record in the store.
   */
  put(value: any, key?: any): IDBRequest {
    this._transaction._assertActive();
    this._transaction._assertWritable();
    // Spec: an explicit key argument on an in-line-key (keyPath) store is a
    // DataError — previously it silently re-keyed the record. (ENG-23134)
    if (key !== undefined && this.keyPath !== null) {
      throw new DOMException(
        'The object store uses in-line keys and the key parameter was provided.',
        'DataError',
      );
    }
    const clonedValue = deserializeValue(serializeValue(value));
    const clonedKey = key === undefined ? undefined : deserializeKey(serializeKey(key));
    if (this.keyPath !== null) {
      const inlineKey = extractKeyPath(clonedValue, this.keyPath);
      if (inlineKey !== undefined && !isValidKey(inlineKey)) {
        throw new DOMException('The keyPath value is not a valid key.', 'DataError');
      }
    }
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        const { key: resolvedKey, value: storedValue } = this._resolveKeyAndValue(clonedValue, clonedKey);
        this._putRecord(resolvedKey, storedValue);
        request._resolve(resolvedKey);
      } catch (e: any) {
        request._reject(e instanceof DOMException ? e : new DOMException(e.message, 'DataError'));
      }
    });
    return request;
  }

  /**
   * Retrieve a record by key.
   */
  get(query: any): IDBRequest {
    this._transaction._assertActive();
    // Spec: DataError for undefined/invalid keys (booleans, null, ...) —
    // previously these silently no-opped. (ENG-23134)
    if (!(query instanceof IDBKeyRange) && !isValidKey(query)) {
      throw new DOMException('The parameter is not a valid key.', 'DataError');
    }
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        if (query instanceof IDBKeyRange) {
          // Push the range + "first match" into SQL: only the smallest matching
          // row is fetched and deserialized, not the whole table. (ENG-22999)
          const { sql, params } = this._selectRange('value', query, 'asc', 1);
          const row = this._db._get(sql, params);
          request._resolve(row ? deserializeValue(row.value) : undefined);
        } else {
          const value = this._getRecord(query);
          request._resolve(value);
        }
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
  }

  /**
   * Retrieve the key of the first record matching.
   */
  getKey(query: any): IDBRequest {
    this._transaction._assertActive();
    // Spec: DataError for undefined/invalid keys (booleans, null, ...) —
    // previously these silently no-opped. (ENG-23134)
    if (!(query instanceof IDBKeyRange) && !isValidKey(query)) {
      throw new DOMException('The parameter is not a valid key.', 'DataError');
    }
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        if (query instanceof IDBKeyRange) {
          // Smallest matching key only — filtered and ordered in SQL. (ENG-22999)
          const { sql, params } = this._selectRange('key', query, 'asc', 1);
          const row = this._db._get(sql, params);
          request._resolve(row ? deserializeKey(row.key) : undefined);
        } else {
          // Existence must be tested against the row, not the deserialized value:
          // structured clone permits a stored `undefined`, so inferring absence
          // from `value === undefined` reported a real record as missing.
          // (ENG-23026)
          request._resolve(this._hasRecord(query) ? canonicalizeKey(query) : undefined);
        }
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
  }

  /**
   * Retrieve all records, optionally filtered by key range.
   */
  getAll(query?: any, count?: number): IDBRequest {
    this._transaction._assertActive();
    this._validateQuery(query);
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        // Filter, order and limit in SQL so only the matching values are read
        // and deserialized instead of the entire table. (ENG-22999)
        const range = this._queryRange(query);
        // count of 0 (or absent) means "all" per the retrieve-multiple algorithm;
        // only a positive count becomes a SQL LIMIT (0 must NOT become LIMIT 0).
        // (ENG-23026)
        const limit = count !== undefined && count > 0 ? count : undefined;
        const { sql, params } = this._selectRange('value', range, 'asc', limit);
        const rows = this._db._all(sql, params);
        request._resolve(rows.map((r: any) => deserializeValue(r.value)));
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
  }

  /**
   * Retrieve all keys, optionally filtered.
   */
  getAllKeys(query?: any, count?: number): IDBRequest {
    this._transaction._assertActive();
    this._validateQuery(query);
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        // Key column only, filtered/ordered/limited in SQL. (ENG-22999)
        const range = this._queryRange(query);
        // count of 0 (or absent) means "all" per the retrieve-multiple algorithm;
        // only a positive count becomes a SQL LIMIT (0 must NOT become LIMIT 0).
        // (ENG-23026)
        const limit = count !== undefined && count > 0 ? count : undefined;
        const { sql, params } = this._selectRange('key', range, 'asc', limit);
        const rows = this._db._all(sql, params);
        request._resolve(rows.map((r: any) => deserializeKey(r.key)));
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
  }

  /**
   * Delete a record by key or key range.
   */
  delete(query: any): IDBRequest {
    this._transaction._assertActive();
    this._transaction._assertWritable();
    // Spec: DataError for undefined/invalid keys (booleans, null, ...) —
    // previously these silently no-opped. (ENG-23134)
    if (!(query instanceof IDBKeyRange) && !isValidKey(query)) {
      throw new DOMException('The parameter is not a valid key.', 'DataError');
    }
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        if (query instanceof IDBKeyRange) {
          // Delete the matching range directly in SQL — no scan, no per-row key
          // deserialization, a single statement. (ENG-22999)
          const { where, params } = this._rangeConds(query);
          // First remove the companion index rows for the records about to be
          // deleted (identified via the store's keyenc range subquery), then the
          // store rows themselves. (ENG-23016)
          if (this._indexes.size > 0) {
            this._ensureIndexData();
            this._db._exec(
              `DELETE FROM "${this._indexTableName()}" WHERE pk IN (SELECT key FROM "${this._tableName}"${where})`,
              params,
            );
          }
          this._db._exec(`DELETE FROM "${this._tableName}"${where}`, params);
        } else {
          this._deleteRecord(query);
        }
        request._resolve(undefined);
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
  }

  /**
   * Delete all records in the store.
   */
  clear(): IDBRequest {
    this._transaction._assertActive();
    this._transaction._assertWritable();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        this._clearRecords();
        request._resolve(undefined);
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
  }

  /**
   * Count records, optionally filtered.
   */
  count(query?: any): IDBRequest {
    this._transaction._assertActive();
    this._validateQuery(query);
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        if (query === undefined || query === null) {
          request._resolve(this._countRecords());
        } else {
          // COUNT(*) with the range pushed into a keyenc WHERE clause — no rows
          // are materialized in JS at all. (ENG-22999)
          const range = query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
          const { where, params } = this._rangeConds(range);
          const row = this._db._get(
            `SELECT COUNT(*) as cnt FROM "${this._tableName}"${where}`,
            params,
          );
          request._resolve(row ? row.cnt : 0);
        }
      } catch (e: any) {
        request._reject(e);
      }
    });
    return request;
  }

  /**
   * Create an index on this object store. Only valid during upgradeneeded.
   */
  createIndex(name: string, keyPath: string | string[], options?: IDBIndexParameters): IDBIndex {
    // Only valid inside an active versionchange (upgradeneeded) transaction —
    // previously there was no check at all, so runtime code could mutate the
    // schema outside any upgrade. (ENG-23117)
    if (this._transaction._mode !== 'versionchange') {
      throw new DOMException(
        'createIndex can only be called during an upgrade (versionchange) transaction',
        'InvalidStateError',
      );
    }
    this._transaction._assertActive();
    if (this._indexes.has(name)) {
      throw new DOMException(
        `Index "${name}" already exists`,
        'ConstraintError',
      );
    }
    const index = new IDBIndex(name, keyPath, options ?? {}, this);
    this._indexes.set(name, index);

    // Persist index metadata
    this._db._saveIndexMeta(this.name, name, keyPath, options ?? {});

    // Build this index's rows in the companion key table from whatever records
    // the store already holds, so index queries are SQL-backed immediately even
    // when the index is added to a populated store during a later upgrade.
    // (ENG-23016)
    this._ensureIndexData();
    this._backfillIndex(name);

    return index;
  }

  /**
   * Delete an index from this object store. Only valid during upgradeneeded.
   */
  deleteIndex(name: string): void {
    // Only valid inside an active versionchange transaction (see createIndex).
    // (ENG-23117)
    if (this._transaction._mode !== 'versionchange') {
      throw new DOMException(
        'deleteIndex can only be called during an upgrade (versionchange) transaction',
        'InvalidStateError',
      );
    }
    this._transaction._assertActive();
    if (!this._indexes.has(name)) {
      throw new DOMException(
        `Index "${name}" does not exist`,
        'NotFoundError',
      );
    }
    // Drop this index's companion rows before removing it from the store (while
    // the store still has an index, so the table is ensured to exist). (ENG-23016)
    this._ensureIndexData();
    this._db._exec(`DELETE FROM "${this._indexTableName()}" WHERE idx = ?`, [name]);
    this._indexes.delete(name);
    this._db._deleteIndexMeta(this.name, name);
  }

  /**
   * Get a reference to an index by name.
   */
  index(name: string): IDBIndex {
    const idx = this._indexes.get(name);
    if (!idx) {
      throw new DOMException(
        `Index "${name}" does not exist on object store "${this.name}"`,
        'NotFoundError',
      );
    }
    return idx;
  }

  /**
   * Open a cursor over the object store.
   */
  openCursor(query?: any, direction?: IDBCursorDirection): IDBRequest {
    this._transaction._assertActive();
    this._validateQuery(query);
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        // Stream the matching rows in bounded batches (keyset pagination over the
        // unique keyenc column) instead of materializing the whole matching set,
        // so an unbounded cursor over a huge store holds O(batch) rows and defers
        // value deserialization to each batch rather than up front. (ENG-23016)
        const dir = direction ?? 'next';
        const stream = this._cursorStreamer(this._queryRange(query), dir, true);
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
   * Open a key cursor over the object store.
   */
  openKeyCursor(query?: any, direction?: IDBCursorDirection): IDBRequest {
    this._transaction._assertActive();
    this._validateQuery(query);
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    this._transaction._enqueueOp(request, () => {
      try {
        // A key cursor never exposes values: stream only the key column (no value
        // deserialization) in bounded batches and yield a plain IDBCursor rather
        // than an IDBCursorWithValue. (ENG-23026 / ENG-23016)
        const dir = direction ?? 'next';
        const stream = this._cursorStreamer(this._queryRange(query), dir, false);
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

  /**
   * @internal - Build a bounded-memory streaming fetcher for an object-store
   * cursor. Object-store keys (hence `keyenc`) are unique, so keyset pagination
   * with a strict keyenc bookmark yields every matching row exactly once in
   * direction order. A true single-statement native row iterator
   * (SQLite statement.iterate held across microtasks) remains a native-bridge
   * follow-up — the JS sqlite bridge exposes only exec/get/all — so we page with
   * LIMIT + a keyenc bookmark here. (ENG-23016)
   */
  _cursorStreamer(range: IDBKeyRange | null, dir: IDBCursorDirection, wantValue: boolean): CursorStream {
    const sqlDir = dir === 'prev' || dir === 'prevunique' ? 'desc' : 'asc';
    const cols = wantValue ? 'key, value, keyenc' : 'key, keyenc';
    const fetch = (after: string | null, target: string | null) => {
      const conds: string[] = [];
      const params: any[] = [];
      if (range) {
        if (range.lower !== undefined) {
          conds.push(range.lowerOpen ? 'keyenc > ?' : 'keyenc >= ?');
          params.push(encodeOrderedKey(range.lower));
        }
        if (range.upper !== undefined) {
          conds.push(range.upperOpen ? 'keyenc < ?' : 'keyenc <= ?');
          params.push(encodeOrderedKey(range.upper));
        }
      }
      if (after !== null) {
        conds.push(sqlDir === 'asc' ? 'keyenc > ?' : 'keyenc < ?');
        params.push(after);
      }
      if (target !== null) {
        conds.push(sqlDir === 'asc' ? 'keyenc >= ?' : 'keyenc <= ?');
        params.push(target);
      }
      const where = conds.length ? ' WHERE ' + conds.join(' AND ') : '';
      const sql =
        `SELECT ${cols} FROM "${this._tableName}"${where} ` +
        `ORDER BY keyenc ${sqlDir === 'desc' ? 'DESC' : 'ASC'} LIMIT ?`;
      params.push(IDB_CURSOR_BATCH);
      return this._db._all(sql, params).map((r: any) => {
        const key = deserializeKey(r.key);
        return {
          key,
          primaryKey: key,
          value: wantValue ? deserializeValue(r.value) : undefined,
          // Store keys are unique, so the keyenc alone is the keyset bookmark.
          bookmark: r.keyenc,
        };
      });
    };
    return { fetch, batchSize: IDB_CURSOR_BATCH };
  }

  // ================================================================
  // Internal SQLite-backed operations
  // ================================================================

  /** @internal */
  _ensureTable(): void {
    this._migrateLegacyTables();
    this._db._exec(
      `CREATE TABLE IF NOT EXISTS "${this._tableName}" (key TEXT PRIMARY KEY, value BLOB, keyenc TEXT)`
    );
    // Ensure the order-preserving `keyenc` column + index exist and backfill
    // any store that predates it. Cached per-connection so this is off the hot
    // path (see IDBDatabase._ensureKeyEnc). (ENG-22999)
    this._db._ensureKeyEnc(this._tableName);
    // The autoIncrement key generator is computed lazily and cached at the
    // database level (see IDBDatabase._nextAutoIncrement); it is intentionally
    // NOT recomputed here, so constructing a store per transaction no longer
    // scans and parses every key.
  }

  /**
   * @internal - Move tables created by the old lossy sanitizer to this store's
   * collision-free table names. Only names whose encoding changed (uppercase,
   * punctuation, unicode, ...) take this path; a legacy table is left alone
   * when it is (ambiguously) the CURRENT table of some other store — i.e. when
   * the old encoding had already merged two stores, the safe-named store keeps
   * the shared data. Runs inside the owning transaction's BEGIN when there is
   * one, so an abort also rolls the rename back. (ENG-23134)
   */
  _migrateLegacyTables(): void {
    const legacy = legacyStoreTableName(this.name);
    if (legacy === this._tableName) return; // encoding unchanged for this name
    if (this._db._keyencReady.has(this._tableName)) return; // already ensured

    // lower(): SQLite identifiers are ASCII case-insensitive, so existence
    // must be tested the way ALTER/DROP would resolve the name. (ENG-23134)
    const tableExists = (t: string) =>
      !!this._db._get(`SELECT name FROM sqlite_master WHERE type = 'table' AND lower(name) = lower(?)`, [t]);

    if (!tableExists(this._tableName) && tableExists(legacy) && !this._db._tableNameClaimed(legacy, this.name)) {
      this._db._exec(`ALTER TABLE "${legacy}" RENAME TO "${this._tableName}"`);
      // The keyenc index keeps its old name across a table rename; drop it so
      // _ensureKeyEnc recreates it under the new table's name.
      this._db._exec(`DROP INDEX IF EXISTS "${legacy}_keyenc"`);
    }

    const legacyIdx = legacyIndexTableName(this.name);
    const idxTable = this._indexTableName();
    if (!tableExists(idxTable) && tableExists(legacyIdx) && !this._db._tableNameClaimed(legacyIdx, this.name)) {
      this._db._exec(`ALTER TABLE "${legacyIdx}" RENAME TO "${idxTable}"`);
      this._db._exec(`DROP INDEX IF EXISTS "${legacyIdx}_lookup"`);
    }
  }

  /**
   * @internal - Validate a getAll/getAllKeys/count/openCursor query argument:
   * null/undefined selects the whole store, but anything else must be a key
   * range or a valid key — spec throws DataError synchronously (previously
   * e.g. openCursor(true) built a garbage range and silently matched
   * nothing). (ENG-23446)
   */
  _validateQuery(query: any): void {
    if (query === undefined || query === null) return;
    if (!(query instanceof IDBKeyRange) && !isValidKey(query)) {
      throw new DOMException('The parameter is not a valid key.', 'DataError');
    }
  }

  /**
   * @internal - Normalize a get/getAll/openCursor query argument into an
   * IDBKeyRange, or null when the query selects the whole store.
   */
  _queryRange(query: any): IDBKeyRange | null {
    if (query === undefined || query === null) return null;
    return query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
  }

  /**
   * @internal - Build a `keyenc` WHERE clause (and its bound params) for a
   * range. Because encodeOrderedKey() is an order-preserving embedding,
   * `compareKeys(k, bound) >= 0` iff `keyenc(k) >= keyenc(bound)`, so the range
   * membership test becomes a plain SQL comparison. (ENG-22999)
   */
  _rangeConds(range: IDBKeyRange): { where: string; params: any[] } {
    const conds: string[] = [];
    const params: any[] = [];
    if (range.lower !== undefined) {
      conds.push(range.lowerOpen ? 'keyenc > ?' : 'keyenc >= ?');
      params.push(encodeOrderedKey(range.lower));
    }
    if (range.upper !== undefined) {
      conds.push(range.upperOpen ? 'keyenc < ?' : 'keyenc <= ?');
      params.push(encodeOrderedKey(range.upper));
    }
    return { where: conds.length ? ' WHERE ' + conds.join(' AND ') : '', params };
  }

  /**
   * @internal - Build a SELECT that filters by an optional range, orders by
   * `keyenc` in the given direction, and optionally limits the row count. All
   * three push into SQL. (ENG-22999)
   */
  _selectRange(
    columns: string,
    range: IDBKeyRange | null,
    dir: 'asc' | 'desc' | null,
    limit?: number,
  ): { sql: string; params: any[] } {
    const { where, params } = range ? this._rangeConds(range) : { where: '', params: [] as any[] };
    let sql = `SELECT ${columns} FROM "${this._tableName}"${where}`;
    if (dir) sql += ` ORDER BY keyenc ${dir === 'desc' ? 'DESC' : 'ASC'}`;
    if (limit !== undefined && limit >= 0) {
      sql += ' LIMIT ?';
      params.push(limit);
    }
    return { sql, params };
  }

  /**
   * @internal - Resolve the record's key and the value to store. When the key
   * generator supplies the key for an in-line-key store, the key is injected
   * into a structured CLONE of the value — per spec the injection happens on
   * the clone, so the caller's object is never mutated (previously
   * `store.add(o)` left `o.id` set afterwards). (ENG-23446)
   */
  _resolveKeyAndValue(value: any, explicitKey?: any): { key: any; value: any } {
    if (explicitKey !== undefined) {
      if (!isValidKey(explicitKey)) {
        throw new DOMException('The parameter is not a valid key.', 'DataError');
      }
      if (this.autoIncrement) {
        this._db._noteExplicitKey(this.name, explicitKey);
      }
      // Binary keys resolve to their canonical (ArrayBuffer) form. (ENG-23134)
      return { key: canonicalizeKey(explicitKey), value };
    }
    if (this.keyPath !== null) {
      const key = extractKeyPath(value, this.keyPath);
      if (key !== undefined) {
        if (!isValidKey(key)) {
          throw new DOMException('The keyPath value is not a valid key.', 'DataError');
        }
        if (this.autoIncrement) {
          this._db._noteExplicitKey(this.name, key);
        }
        return { key: canonicalizeKey(key), value };
      }
    }
    if (this.autoIncrement) {
      const newKey = this._db._nextAutoIncrement(this.name, this._tableName);
      // add()/put() pass their already-owned structured clone here. Inject
      // into that clone directly: cloning it a second time duplicates every
      // attachment (including multi-megabyte BLOBs) solely to add one key.
      if (this.keyPath !== null && typeof this.keyPath === 'string' && typeof value === 'object' && value !== null) {
        setKeyPath(value, this.keyPath, newKey);
        return { key: newKey, value };
      }
      return { key: newKey, value };
    }
    throw new DOMException(
      'No key provided and no keyPath or autoIncrement configured',
      'DataError',
    );
  }

  /**
   * @internal - The key an in-line-key store derives from a value, or
   * undefined when the store is out-of-line or the value has none. Used by
   * cursor.update() to reject values that would re-key the record. (ENG-23134)
   */
  _extractInlineKey(value: any): any {
    return this.keyPath === null ? undefined : extractKeyPath(value, this.keyPath);
  }

  /** @internal */
  _hasRecord(key: any): boolean {
    const row = this._db._get(
      `SELECT 1 FROM "${this._tableName}" WHERE key = ?`,
      [serializeKey(key)]
    );
    return !!row;
  }

  /** @internal */
  _putRecord(key: any, value: any): void {
    const pkSer = serializeKey(key);
    // Compute the record's index entries and detect any unique-index conflict
    // BEFORE writing the store row, so a ConstraintError leaves the store
    // untouched even if the failing request's error is handled and the
    // transaction continues. Returns null when the store has no indexes.
    // (ENG-23016)
    const applyIndexes = this._prepareIndexMaintenance(key, value, pkSer);
    // The versioned BLOB envelope preserves Date/Map/etc. while storing binary
    // attachments as raw bytes (no base64/number-array amplification). SQLite's
    // dynamic typing also accepts BLOBs in legacy value-TEXT tables; old TEXT
    // rows remain readable and migrate lazily on rewrite. `keyenc` holds the
    // order-preserving encoding used for range/ORDER BY. (ENG-22999/ENG-24277)
    this._db._exec(
      `INSERT OR REPLACE INTO "${this._tableName}" (key, value, keyenc) VALUES (?, ?, ?)`,
      [pkSer, serializeValue(value), encodeOrderedKey(key)]
    );
    if (applyIndexes) applyIndexes();
  }

  /** @internal */
  _getRecord(key: any): any {
    const row = this._db._get(
      `SELECT value FROM "${this._tableName}" WHERE key = ?`,
      [serializeKey(key)]
    );
    return row ? deserializeValue(row.value) : undefined;
  }

  /** @internal */
  _deleteRecord(key: any): void {
    const pkSer = serializeKey(key);
    // Remove the record's companion index rows alongside the store row. (ENG-23016)
    if (this._indexes.size > 0) {
      this._ensureIndexData();
      this._db._exec(`DELETE FROM "${this._indexTableName()}" WHERE pk = ?`, [pkSer]);
    }
    this._db._exec(
      `DELETE FROM "${this._tableName}" WHERE key = ?`,
      [pkSer]
    );
  }

  /** @internal */
  _clearRecords(): void {
    // Clearing records must NOT reset the autoIncrement key generator. Per spec
    // the generator is reset only when the object store is deleted or the
    // transaction is aborted — never by clear()/delete() — so a later add()
    // keeps counting up rather than reissuing an already-used key. (ENG-23026)
    this._db._exec(`DELETE FROM "${this._tableName}"`);
    // Clear the companion index rows too, so indexes reflect the empty store.
    // (ENG-23016)
    if (this._indexes.size > 0) {
      this._ensureIndexData();
      this._db._exec(`DELETE FROM "${this._indexTableName()}"`);
    }
  }

  /** @internal */
  _countRecords(): number {
    const row = this._db._get(`SELECT COUNT(*) as cnt FROM "${this._tableName}"`);
    return row ? row.cnt : 0;
  }

  // ================================================================
  // Per-index SQLite key tables (ENG-23016)
  //
  // Each store has ONE companion table `idb_index_<store>` holding a row per
  // (index, index-key entry): `keyenc`/`pkenc` are the order-preserving
  // encodings of the index key and primary key (so range + ORDER BY run in
  // SQL, giving index-key order with a primary-key tiebreak), while `ikey`/`pk`
  // are the tagged-JSON index key and primary key. A multiEntry array key
  // expands to one row per distinct valid element. Index reads then filter,
  // order and limit in SQL and join back to the store for values, instead of
  // scanning + deserializing the whole store in JS (the deferred "index-backed
  // lookups" piece of ENG-22999 / finding 3 of ENG-22974).
  // ================================================================

  /** @internal - The store's companion index-key table name. */
  _indexTableName(): string {
    return indexTableName(this.name);
  }

  /**
   * @internal - Ensure the companion index table + lookup index exist and, on
   * the first open of a database created before per-index tables existed,
   * backfill every index from the store's rows. Memoized per connection; the
   * persistent `idxdata:<store>` meta marker makes the backfill run at most once
   * ever. Mirrors _ensureKeyEnc so it stays off the hot path.
   */
  _ensureIndexData(): void {
    if (this._indexes.size === 0) return;
    const table = this._indexTableName();
    if (this._db._indexDataReady.has(table)) return;
    this._db._exec(
      `CREATE TABLE IF NOT EXISTS "${table}" (idx TEXT, keyenc TEXT, pkenc TEXT, ikey TEXT, pk TEXT)`,
    );
    this._db._exec(
      `CREATE INDEX IF NOT EXISTS "${table}_lookup" ON "${table}"(idx, keyenc, pkenc)`,
    );
    const marker = this._db._get(`SELECT value FROM _idb_meta WHERE key = ?`, [`idxdata:${this.name}`]);
    if (!marker || marker.value !== '1') {
      for (const name of this._indexes.keys()) this._backfillIndex(name);
      this._db._exec(
        `INSERT OR REPLACE INTO _idb_meta (key, value) VALUES (?, '1')`,
        [`idxdata:${this.name}`],
      );
    }
    this._db._indexDataReady.add(table);
  }

  /** @internal - Rebuild one index's companion rows from the store's records. */
  _backfillIndex(indexName: string): void {
    const index = this._indexes.get(indexName);
    if (!index) return;
    const table = this._indexTableName();
    this._db._exec(`DELETE FROM "${table}" WHERE idx = ?`, [indexName]);
    const rows = this._db._all(`SELECT key, value FROM "${this._tableName}"`);
    for (const r of rows) {
      const primaryKey = deserializeKey(r.key);
      const value = deserializeValue(r.value);
      for (const e of this._indexEntries(index, primaryKey, value)) {
        this._db._exec(
          `INSERT INTO "${table}" (idx, keyenc, pkenc, ikey, pk) VALUES (?, ?, ?, ?, ?)`,
          [indexName, e.keyenc, e.pkenc, e.ikey, e.pk],
        );
      }
    }
  }

  /**
   * @internal - The companion rows a record contributes to one index. Empty
   * when the record has no valid key at the index's key path. A multiEntry
   * index over an array key yields one entry per distinct valid element.
   */
  _indexEntries(
    index: IDBIndex,
    primaryKey: any,
    value: any,
  ): Array<{ keyenc: string; pkenc: string; ikey: string; pk: string }> {
    const raw = extractKeyPath(value, index.keyPath);
    if (raw === undefined) return [];
    const pkenc = encodeOrderedKey(primaryKey);
    const pk = serializeKey(primaryKey);

    if (index.multiEntry && Array.isArray(raw)) {
      const out: Array<{ keyenc: string; pkenc: string; ikey: string; pk: string }> = [];
      const seen = new Set<string>();
      for (const el of raw) {
        if (!isValidKey(el)) continue; // skip non-key array elements
        const keyenc = encodeOrderedKey(el);
        if (seen.has(keyenc)) continue; // dedupe duplicate subkeys
        seen.add(keyenc);
        out.push({ keyenc, pkenc, ikey: serializeKey(el), pk });
      }
      return out;
    }

    if (!isValidKey(raw)) return []; // an index value that isn't a valid key is not indexed
    return [{ keyenc: encodeOrderedKey(raw), pkenc, ikey: serializeKey(raw), pk }];
  }

  /**
   * @internal - Detect unique-index conflicts for a record and return a closure
   * that applies its index-row updates, or null when the store has no indexes.
   * The conflict check runs before the caller writes the store row so a
   * ConstraintError never leaves a half-written record. (ENG-23016)
   */
  _prepareIndexMaintenance(primaryKey: any, value: any, pkSer: string): (() => void) | null {
    if (this._indexes.size === 0) return null;
    this._ensureIndexData();
    const table = this._indexTableName();
    const plan: Array<{ name: string; entries: Array<{ keyenc: string; pkenc: string; ikey: string; pk: string }> }> = [];
    for (const [name, index] of this._indexes) {
      const entries = this._indexEntries(index, primaryKey, value);
      if (index.unique) {
        for (const e of entries) {
          const clash = this._db._get(
            `SELECT 1 FROM "${table}" WHERE idx = ? AND keyenc = ? AND pk <> ? LIMIT 1`,
            [name, e.keyenc, pkSer],
          );
          if (clash) {
            throw new DOMException(
              `Unable to add key to index "${name}": at least one key does not satisfy the uniqueness requirements.`,
              'ConstraintError',
            );
          }
        }
      }
      plan.push({ name, entries });
    }
    return () => {
      for (const { name, entries } of plan) {
        this._db._exec(`DELETE FROM "${table}" WHERE idx = ? AND pk = ?`, [name, pkSer]);
        for (const e of entries) {
          this._db._exec(
            `INSERT INTO "${table}" (idx, keyenc, pkenc, ikey, pk) VALUES (?, ?, ?, ?, ?)`,
            [name, e.keyenc, e.pkenc, e.ikey, e.pk],
          );
        }
      }
    };
  }

  /**
   * @internal - WHERE clause for an index query: the index name plus an optional
   * order-preserving `keyenc` range, matching _rangeConds but qualified for the
   * joined index table alias `ix`.
   */
  _indexWhere(indexName: string, range: IDBKeyRange | null): { where: string; params: any[] } {
    const conds = ['ix.idx = ?'];
    const params: any[] = [indexName];
    if (range) {
      if (range.lower !== undefined) {
        conds.push(range.lowerOpen ? 'ix.keyenc > ?' : 'ix.keyenc >= ?');
        params.push(encodeOrderedKey(range.lower));
      }
      if (range.upper !== undefined) {
        conds.push(range.upperOpen ? 'ix.keyenc < ?' : 'ix.keyenc <= ?');
        params.push(encodeOrderedKey(range.upper));
      }
    }
    return { where: ' WHERE ' + conds.join(' AND '), params };
  }

  /** @internal - Values matching an index query, in index-key (then primary-key) order. */
  _indexGetValues(indexName: string, range: IDBKeyRange | null, limit?: number): any[] {
    this._ensureIndexData();
    const { where, params } = this._indexWhere(indexName, range);
    let sql =
      `SELECT s.value AS value FROM "${this._indexTableName()}" ix ` +
      `JOIN "${this._tableName}" s ON s.key = ix.pk${where} ORDER BY ix.keyenc ASC, ix.pkenc ASC`;
    if (limit !== undefined && limit > 0) {
      sql += ' LIMIT ?';
      params.push(limit);
    }
    return this._db._all(sql, params).map((r: any) => deserializeValue(r.value));
  }

  /** @internal - Primary keys matching an index query, in index-key order. */
  _indexGetKeys(indexName: string, range: IDBKeyRange | null, limit?: number): any[] {
    this._ensureIndexData();
    const { where, params } = this._indexWhere(indexName, range);
    let sql = `SELECT ix.pk AS pk FROM "${this._indexTableName()}" ix${where} ORDER BY ix.keyenc ASC, ix.pkenc ASC`;
    if (limit !== undefined && limit > 0) {
      sql += ' LIMIT ?';
      params.push(limit);
    }
    return this._db._all(sql, params).map((r: any) => deserializeKey(r.pk));
  }

  /** @internal - COUNT of index rows matching a query — no rows materialized in JS. */
  _indexCount(indexName: string, range: IDBKeyRange | null): number {
    this._ensureIndexData();
    const { where, params } = this._indexWhere(indexName, range);
    const row = this._db._get(
      `SELECT COUNT(*) AS cnt FROM "${this._indexTableName()}" ix${where}`,
      params,
    );
    return row ? row.cnt : 0;
  }

  /**
   * @internal - Build a bounded-memory streaming fetcher for an INDEX cursor.
   * (ENG-23134)
   *
   * The previous implementation materialized every matching record up front
   * and iterated the in-memory snapshot, so a record deleted mid-iteration
   * within the same readwrite transaction was still delivered (with its stale
   * value) and one inserted ahead was never visited — disagreeing with the
   * store cursors, which re-query per batch. This streams the same way:
   *
   *  - Index keys are NOT unique, so `next`/`prev` paginate on the composite
   *    (keyenc, pkenc) bookmark, ordered (and for `prev`, DESCENDING on the
   *    primary key too — the spec's duplicate-key order, which the old
   *    key-only JS sort got backwards).
   *  - `nextunique`/`prevunique` GROUP BY keyenc taking MIN(pkenc) — the
   *    spec's "first record of each key group" for BOTH unique directions —
   *    and paginate on keyenc alone. This replaces the JSON.stringify dedupe
   *    that collapsed all binary keys into one group.
   *
   * Like store cursors, each batch (IDB_CURSOR_BATCH rows) is a small window:
   * liveness is per-batch, not per-row.
   */
  _indexCursorStreamer(
    indexName: string,
    range: IDBKeyRange | null,
    dir: IDBCursorDirection,
    wantValue: boolean,
  ): CursorStream {
    const desc = dir === 'prev' || dir === 'prevunique';
    const unique = dir === 'nextunique' || dir === 'prevunique';
    const fetch = (after: any, target: string | null) => {
      this._ensureIndexData();
      const { where, params } = this._indexWhere(indexName, range);
      const conds: string[] = [];
      if (after !== null && after !== undefined) {
        if (unique) {
          conds.push(desc ? 'ix.keyenc < ?' : 'ix.keyenc > ?');
          params.push(after.k);
        } else {
          conds.push(desc
            ? '(ix.keyenc < ? OR (ix.keyenc = ? AND ix.pkenc < ?))'
            : '(ix.keyenc > ? OR (ix.keyenc = ? AND ix.pkenc > ?))');
          params.push(after.k, after.k, after.p);
        }
      }
      if (target !== null) {
        conds.push(desc ? 'ix.keyenc <= ?' : 'ix.keyenc >= ?');
        params.push(target);
      }
      const whereFull = where + (conds.length ? ' AND ' + conds.join(' AND ') : '');
      const valueCol = wantValue ? ', s.value AS value' : '';
      const from = wantValue
        ? `"${this._indexTableName()}" ix JOIN "${this._tableName}" s ON s.key = ix.pk`
        : `"${this._indexTableName()}" ix`;
      const ord = desc ? 'DESC' : 'ASC';
      let sql: string;
      if (unique) {
        // SQLite bare-column semantics: with a lone MIN() aggregate the other
        // selected columns come from the row where the minimum was found.
        sql =
          `SELECT ix.ikey AS ikey, ix.pk AS pk, ix.keyenc AS keyenc, MIN(ix.pkenc) AS pkenc${valueCol} ` +
          `FROM ${from}${whereFull} GROUP BY ix.keyenc ORDER BY ix.keyenc ${ord} LIMIT ?`;
      } else {
        sql =
          `SELECT ix.ikey AS ikey, ix.pk AS pk, ix.keyenc AS keyenc, ix.pkenc AS pkenc${valueCol} ` +
          `FROM ${from}${whereFull} ORDER BY ix.keyenc ${ord}, ix.pkenc ${ord} LIMIT ?`;
      }
      params.push(IDB_CURSOR_BATCH);
      return this._db._all(sql, params).map((r: any) => ({
        key: deserializeKey(r.ikey),
        primaryKey: deserializeKey(r.pk),
        value: wantValue ? deserializeValue(r.value) : undefined,
        bookmark: { k: r.keyenc, p: r.pkenc },
      }));
    };
    return { fetch, batchSize: IDB_CURSOR_BATCH };
  }
}

/**
 * Set a value at a key path on an object.
 */
function setKeyPath(obj: any, keyPath: string, value: any): void {
  const parts = keyPath.split('.');
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (current[parts[i]] === undefined) {
      current[parts[i]] = {};
    }
    current = current[parts[i]];
  }
  current[parts[parts.length - 1]] = value;
}
