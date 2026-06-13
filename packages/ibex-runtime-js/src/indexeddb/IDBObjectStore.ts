/**
 * IDBObjectStore - IndexedDB Object Store
 *
 * Represents an object store in the database. Backed by a SQLite table.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBObjectStore
 */

import { IDBRequest } from './IDBRequest';
import { IDBIndex, type IDBIndexParameters, extractKeyPath } from './IDBIndex';
import { IDBKeyRange, compareKeys } from './IDBKeyRange';
import { IDBCursorWithValue, type IDBCursorDirection } from './IDBCursor';
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
  _autoIncrementValue: number = 0;
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
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      if (query instanceof IDBKeyRange) {
        const records = this._getAllRecords();
        const match = records.find((r: any) => query.includes(r.key));
        request._resolve(match ? match.key : undefined);
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
      request._resolve(records.map((r: any) => r.key));
    } catch (e: any) {
      request._reject(e);
    }
    return request;
  }

  /**
   * Delete a record by key or key range.
   */
  delete(query: any): IDBRequest {
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      if (query instanceof IDBKeyRange) {
        const records = this._getAllRecords();
        for (const r of records) {
          if (query.includes(r.key)) {
            this._deleteRecord(r.key);
          }
        }
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
    const request = new IDBRequest();
    request.source = this;
    request.transaction = this._transaction;
    try {
      if (query === undefined || query === null) {
        request._resolve(this._countRecords());
      } else {
        const range = query instanceof IDBKeyRange ? query : IDBKeyRange.only(query);
        const records = this._getAllRecords();
        request._resolve(records.filter((r: any) => range.includes(r.key)).length);
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
    // Load auto-increment counter by scanning all keys in JS.
    // We cannot rely on SQLite's typeof() or CAST() on JSON-encoded text keys,
    // so we parse them in JS and find the max numeric key.
    if (this.autoIncrement) {
      const rows = this._db._all(`SELECT key FROM "${this._tableName}"`);
      let maxKey = 0;
      for (const row of rows) {
        try {
          const parsed = JSON.parse(row.key);
          if (typeof parsed === 'number' && !isNaN(parsed) && parsed > maxKey) {
            maxKey = parsed;
          }
        } catch (_) {
          // Skip non-parseable keys
        }
      }
      this._autoIncrementValue = maxKey;
    }
  }

  /** @internal */
  _resolveKey(value: any, explicitKey?: any): any {
    if (explicitKey !== undefined) {
      return explicitKey;
    }
    if (this.keyPath !== null) {
      const key = extractKeyPath(value, this.keyPath);
      if (key !== undefined) return key;
    }
    if (this.autoIncrement) {
      this._autoIncrementValue++;
      const newKey = this._autoIncrementValue;
      // If keyPath exists, set the key on the value
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
      [JSON.stringify(key)]
    );
    return !!row;
  }

  /** @internal */
  _putRecord(key: any, value: any): void {
    const serializedKey = JSON.stringify(key);
    const serializedValue = JSON.stringify(value);
    this._db._exec(
      `INSERT OR REPLACE INTO "${this._tableName}" (key, value) VALUES (?, ?)`,
      [serializedKey, serializedValue]
    );
  }

  /** @internal */
  _getRecord(key: any): any {
    const row = this._db._get(
      `SELECT value FROM "${this._tableName}" WHERE key = ?`,
      [JSON.stringify(key)]
    );
    return row ? JSON.parse(row.value) : undefined;
  }

  /** @internal */
  _deleteRecord(key: any): void {
    this._db._exec(
      `DELETE FROM "${this._tableName}" WHERE key = ?`,
      [JSON.stringify(key)]
    );
  }

  /** @internal */
  _clearRecords(): void {
    this._db._exec(`DELETE FROM "${this._tableName}"`);
    if (this.autoIncrement) {
      this._autoIncrementValue = 0;
    }
  }

  /** @internal */
  _countRecords(): number {
    const row = this._db._get(`SELECT COUNT(*) as cnt FROM "${this._tableName}"`);
    return row ? row.cnt : 0;
  }

  /** @internal */
  _getAllRecords(): Array<{ key: any; value: any }> {
    const rows = this._db._all(`SELECT key, value FROM "${this._tableName}"`);
    const records = rows.map((r: any) => ({
      key: JSON.parse(r.key),
      value: JSON.parse(r.value),
    }));
    // Sort in JS using IndexedDB key comparison (number < string < Date < Array)
    // to avoid lexicographic issues with SQLite text-based ORDER BY.
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

