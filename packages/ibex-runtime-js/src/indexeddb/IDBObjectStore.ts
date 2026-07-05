/**
 * IDBObjectStore - IndexedDB Object Store
 *
 * Represents an object store in the database. Backed by a SQLite table.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBObjectStore
 */

import { IDBRequest } from './IDBRequest';
import { IDBIndex, type IDBIndexParameters, extractKeyPath } from './IDBIndex';
import { IDBKeyRange, compareKeys, isValidKey } from './IDBKeyRange';
import { IDBCursorWithValue, type IDBCursorDirection } from './IDBCursor';
import { serializeKey, deserializeKey, serializeValue, deserializeValue } from './serialization';
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
        const records = this._getAllRecords();
        const match = records.find((r: any) => query.includes(r.key));
        request._resolve(match ? match.value : undefined);
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
        const keys = this._getAllKeys();
        const match = keys.find((k: any) => query.includes(k));
        request._resolve(match !== undefined ? match : undefined);
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
      let records = this._getAllRecords();
      if (query !== undefined && query !== null) {
        const range = query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
        records = records.filter((r: any) => range.includes(r.key));
      }
      if (count !== undefined && count >= 0) {
        records = records.slice(0, count);
      }
      request._resolve(records.map((r: any) => r.value));
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
      // Only the keys are needed, so avoid deserializing every record value.
      let keys = this._getAllKeys();
      if (query !== undefined && query !== null) {
        const range = query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
        keys = keys.filter((k: any) => range.includes(k));
      }
      if (count !== undefined && count >= 0) {
        keys = keys.slice(0, count);
      }
      request._resolve(keys);
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
        // Find matching keys (no value deserialization) and delete them in one
        // statement rather than issuing a DELETE per key.
        const matches = this._getAllKeys().filter((k: any) => query.includes(k));
        this._deleteRecords(matches);
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
        const range = query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
        // Count over keys only; no value deserialization.
        const keys = this._getAllKeys();
        request._resolve(keys.filter((k: any) => range.includes(k)).length);
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
      let records = this._getAllRecords();
      if (query !== undefined && query !== null) {
        const range = query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
        records = records.filter((r: any) => range.includes(r.key));
      }
      if (records.length === 0) {
        request._resolve(null);
      } else {
        const cursorRecords = records.map((r: any) => ({
          key: r.key,
          primaryKey: r.key,
          value: r.value,
        }));
        const cursor = new IDBCursorWithValue(this, direction ?? 'next', cursorRecords, request);
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
      `CREATE TABLE IF NOT EXISTS "${this._tableName}" (key TEXT PRIMARY KEY, value TEXT)`
    );
    // The autoIncrement key generator is computed lazily and cached at the
    // database level (see IDBDatabase._nextAutoIncrement); it is intentionally
    // NOT recomputed here, so constructing a store per transaction no longer
    // scans and parses every key.
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
    // Map/Set/undefined that plain JSON silently corrupts.
    this._db._exec(
      `INSERT OR REPLACE INTO "${this._tableName}" (key, value) VALUES (?, ?)`,
      [serializeKey(key), serializeValue(value)]
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

  /** @internal - Delete a batch of keys in a single statement. */
  _deleteRecords(keys: any[]): void {
    if (keys.length === 0) return;
    const placeholders = keys.map(() => '?').join(', ');
    this._db._exec(
      `DELETE FROM "${this._tableName}" WHERE key IN (${placeholders})`,
      keys.map((k) => serializeKey(k))
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

  /** @internal - Deserialize and sort just the keys (no record values). */
  _getAllKeys(): any[] {
    const rows = this._db._all(`SELECT key FROM "${this._tableName}"`);
    const keys = rows.map((r: any) => deserializeKey(r.key));
    keys.sort((a: any, b: any) => compareKeys(a, b));
    return keys;
  }

  /** @internal */
  _getAllRecords(): Array<{ key: any; value: any }> {
    const rows = this._db._all(`SELECT key, value FROM "${this._tableName}"`);
    const records = rows.map((r: any) => ({
      key: deserializeKey(r.key),
      value: deserializeValue(r.value),
    }));
    // Sort in JS using IndexedDB key comparison (number < date < string <
    // binary < array) to avoid lexicographic issues with SQLite text ORDER BY.
    records.sort((a: any, b: any) => compareKeys(a.key, b.key));
    return records;
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
