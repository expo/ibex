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
import { IDBCursorWithValue, type IDBCursorDirection } from './IDBCursor';
import { serializeKey, deserializeKey, serializeValue, deserializeValue, encodeOrderedKey } from './serialization';
import { DOMException, sanitizeName } from './utils';

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
    this._tableName = `idb_store_${sanitizeName(name)}`;

    // Create the SQLite table if it doesn't exist
    this._ensureTable();
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
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      const resolvedKey = this._resolveKey(value, key);
      if (this._hasRecord(resolvedKey)) {
        throw new DOMException(
          `A record with key ${JSON.stringify(resolvedKey)} already exists`,
          'ConstraintError',
        );
      }
      this._putRecord(resolvedKey, value);
      request._resolve(resolvedKey);
    } catch (e: any) {
      request._reject(e instanceof DOMException ? e : new DOMException(e.message, 'DataError'));
    }
    return request;
  }

  /**
   * Add or update a record in the store.
   */
  put(value: any, key?: any): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      const resolvedKey = this._resolveKey(value, key);
      this._putRecord(resolvedKey, value);
      request._resolve(resolvedKey);
    } catch (e: any) {
      request._reject(e instanceof DOMException ? e : new DOMException(e.message, 'DataError'));
    }
    return request;
  }

  /**
   * Retrieve a record by key.
   */
  get(query: any): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
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
    return request;
  }

  /**
   * Retrieve the key of the first record matching.
   */
  getKey(query: any): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      if (query instanceof IDBKeyRange) {
        // Smallest matching key only — filtered and ordered in SQL. (ENG-22999)
        const { sql, params } = this._selectRange('key', query, 'asc', 1);
        const row = this._db._get(sql, params);
        request._resolve(row ? deserializeKey(row.key) : undefined);
      } else {
        const value = this._getRecord(query);
        request._resolve(value !== undefined ? query : undefined);
      }
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Retrieve all records, optionally filtered by key range.
   */
  getAll(query?: any, count?: number): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      // Filter, order and limit in SQL so only the matching values are read
      // and deserialized instead of the entire table. (ENG-22999)
      const range = this._queryRange(query);
      const limit = count !== undefined && count >= 0 ? count : undefined;
      const { sql, params } = this._selectRange('value', range, 'asc', limit);
      const rows = this._db._all(sql, params);
      request._resolve(rows.map((r: any) => deserializeValue(r.value)));
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Retrieve all keys, optionally filtered.
   */
  getAllKeys(query?: any, count?: number): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      // Key column only, filtered/ordered/limited in SQL. (ENG-22999)
      const range = this._queryRange(query);
      const limit = count !== undefined && count >= 0 ? count : undefined;
      const { sql, params } = this._selectRange('key', range, 'asc', limit);
      const rows = this._db._all(sql, params);
      request._resolve(rows.map((r: any) => deserializeKey(r.key)));
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Delete a record by key or key range.
   */
  delete(query: any): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      if (query instanceof IDBKeyRange) {
        // Delete the matching range directly in SQL — no scan, no per-row key
        // deserialization, a single statement. (ENG-22999)
        const { where, params } = this._rangeConds(query);
        this._db._exec(`DELETE FROM "${this._tableName}"${where}`, params);
      } else {
        this._deleteRecord(query);
      }
      request._resolve(undefined);
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Delete all records in the store.
   */
  clear(): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      this._clearRecords();
      request._resolve(undefined);
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Count records, optionally filtered.
   */
  count(query?: any): IDBRequest {
    this._transaction._assertActive();
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
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
    return request;
  }

  /**
   * Create an index on this object store. Only valid during upgradeneeded.
   */
  createIndex(name: string, keyPath: string | string[], options?: IDBIndexParameters): IDBIndex {
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

    return index;
  }

  /**
   * Delete an index from this object store. Only valid during upgradeneeded.
   */
  deleteIndex(name: string): void {
    if (!this._indexes.has(name)) {
      throw new DOMException(
        `Index "${name}" does not exist`,
        'NotFoundError',
      );
    }
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
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      // Select only the matching rows, already ordered by the cursor's
      // direction in SQL, so the cursor never scans/deserializes the whole
      // table or re-sorts in JS. Object-store keys are unique, so the ordered
      // rows can be handed to the cursor pre-sorted (nextunique/prevunique are
      // equivalent to next/prev here). (ENG-22999)
      const dir = direction ?? 'next';
      const range = this._queryRange(query);
      const sqlDir = dir === 'prev' || dir === 'prevunique' ? 'desc' : 'asc';
      const { sql, params } = this._selectRange('key, value', range, sqlDir);
      const rows = this._db._all(sql, params);
      if (rows.length === 0) {
        request._resolve(null);
      } else {
        const cursorRecords = rows.map((r: any) => {
          const key = deserializeKey(r.key);
          return { key, primaryKey: key, value: deserializeValue(r.value) };
        });
        const cursor = new IDBCursorWithValue(this, dir, cursorRecords, request, true);
        request._resolve(cursor);
      }
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Open a key cursor over the object store.
   */
  openKeyCursor(query?: any, direction?: IDBCursorDirection): IDBRequest {
    return this.openCursor(query, direction);
  }

  // ================================================================
  // Internal SQLite-backed operations
  // ================================================================

  /** @internal */
  _ensureTable(): void {
    this._db._exec(
      `CREATE TABLE IF NOT EXISTS "${this._tableName}" (key TEXT PRIMARY KEY, value TEXT, keyenc TEXT)`
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

  /** @internal */
  _resolveKey(value: any, explicitKey?: any): any {
    if (explicitKey !== undefined) {
      if (!isValidKey(explicitKey)) {
        throw new DOMException('The parameter is not a valid key.', 'DataError');
      }
      if (this.autoIncrement) {
        this._db._noteExplicitKey(this.name, explicitKey);
      }
      return explicitKey;
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
        return key;
      }
    }
    if (this.autoIncrement) {
      const newKey = this._db._nextAutoIncrement(this.name, this._tableName);
      // If keyPath exists, set the generated key on the value
      if (this.keyPath !== null && typeof this.keyPath === 'string' && typeof value === 'object' && value !== null) {
        setKeyPath(value, this.keyPath, newKey);
      }
      return newKey;
    }
    throw new DOMException(
      'No key provided and no keyPath or autoIncrement configured',
      'DataError',
    );
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
    // Structured (tagged) serialization preserves Date/TypedArray/ArrayBuffer/
    // Map/Set/undefined that plain JSON silently corrupts. The `keyenc` column
    // holds the order-preserving encoding used for range/ORDER BY. (ENG-22999)
    this._db._exec(
      `INSERT OR REPLACE INTO "${this._tableName}" (key, value, keyenc) VALUES (?, ?, ?)`,
      [serializeKey(key), serializeValue(value), encodeOrderedKey(key)]
    );
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
    this._db._exec(
      `DELETE FROM "${this._tableName}" WHERE key = ?`,
      [serializeKey(key)]
    );
  }

  /** @internal */
  _clearRecords(): void {
    this._db._exec(`DELETE FROM "${this._tableName}"`);
    if (this.autoIncrement) {
      this._db._resetAutoIncrement(this.name);
    }
  }

  /** @internal */
  _countRecords(): number {
    const row = this._db._get(`SELECT COUNT(*) as cnt FROM "${this._tableName}"`);
    return row ? row.cnt : 0;
  }

  /**
   * @internal - All records ordered by IndexedDB key order. The ordering is
   * done in SQL via the `keyenc` column, so no JS sort is needed. Still a full
   * scan; used only by IDBIndex, which re-sorts by the index key anyway.
   */
  _getAllRecords(): Array<{ key: any; value: any }> {
    const rows = this._db._all(
      `SELECT key, value FROM "${this._tableName}" ORDER BY keyenc`,
    );
    return rows.map((r: any) => ({
      key: deserializeKey(r.key),
      value: deserializeValue(r.value),
    }));
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
