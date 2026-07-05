/**
 * IDBDatabase - IndexedDB Database
 *
 * Represents an open connection to a database. Backed by a SQLite database.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBDatabase
 */

import { IDBTransaction, type IDBTransactionMode } from './IDBTransaction';
import { IDBObjectStore, type IDBObjectStoreParameters } from './IDBObjectStore';
import { IDBIndex } from './IDBIndex';
import { DOMException, makeDOMStringList, sanitizeName } from './utils';

export class IDBDatabase {
  readonly name: string;
  private _version: number;
  private _objectStores: Map<string, { options: IDBObjectStoreParameters; indexes: Map<string, any>; autoIncrementValue?: number }> = new Map();
  private _closed = false;
  /** @internal - SQLite database wrapper */
  _sqliteDb: any;
  /** @internal - Owning IDBFactory, notified on close() so it can evict its cache */
  _factory: any = null;
  /** @internal - The active versionchange transaction during upgradeneeded, if any */
  _upgradeTransaction: IDBTransaction | null = null;
  /** @internal - EventTarget listeners keyed by event type */
  private _listeners: Record<string, Function[]> = {};

  onclose: ((event: any) => void) | null = null;
  onversionchange: ((event: any) => void) | null = null;
  onerror: ((event: any) => void) | null = null;
  onabort: ((event: any) => void) | null = null;

  constructor(name: string, version: number, sqliteDb: any, factory?: any) {
    this.name = name;
    this._version = version;
    this._sqliteDb = sqliteDb;
    this._factory = factory ?? null;

    // Initialize meta tables
    this._initMeta();
    // Load existing object store definitions
    this._loadStoreDefinitions();
  }

  get version(): number {
    return this._version;
  }

  get objectStoreNames(): any {
    return makeDOMStringList(Array.from(this._objectStores.keys()).sort());
  }

  addEventListener(type: string, fn: Function): void {
    if (!this._listeners[type]) this._listeners[type] = [];
    this._listeners[type].push(fn);
  }

  removeEventListener(type: string, fn: Function): void {
    const list = this._listeners[type];
    if (list) this._listeners[type] = list.filter(f => f !== fn);
  }

  /**
   * Create a new object store. Only valid during upgradeneeded.
   */
  createObjectStore(name: string, options?: IDBObjectStoreParameters): IDBObjectStore {
    // Guard: only allowed during an active versionchange transaction
    if (this._upgradeTransaction && this._upgradeTransaction._state !== 'active') {
      throw new DOMException(
        'Can only be called during upgradeneeded',
        'InvalidStateError',
      );
    }

    if (this._objectStores.has(name)) {
      throw new DOMException(
        `Object store "${name}" already exists`,
        'ConstraintError',
      );
    }

    const opts: IDBObjectStoreParameters = {
      keyPath: options?.keyPath ?? null,
      autoIncrement: options?.autoIncrement ?? false,
    };

    this._objectStores.set(name, { options: opts, indexes: new Map() });

    // Persist store definition to meta table
    this._saveStoreMeta(name, opts);

    // Create the store object with a versionchange transaction
    const txn = this._upgradeTransaction ?? new IDBTransaction(this, [name], 'versionchange');
    const store = new IDBObjectStore(name, opts, txn, this);
    return store;
  }

  /**
   * Delete an object store. Only valid during upgradeneeded.
   */
  deleteObjectStore(name: string): void {
    // Guard: only allowed during an active versionchange transaction
    if (this._upgradeTransaction && this._upgradeTransaction._state !== 'active') {
      throw new DOMException(
        'Can only be called during upgradeneeded',
        'InvalidStateError',
      );
    }

    if (!this._objectStores.has(name)) {
      throw new DOMException(
        `Object store "${name}" does not exist`,
        'NotFoundError',
      );
    }

    // Drop the SQLite table
    const tableName = `idb_store_${sanitizeName(name)}`;
    this._exec(`DROP TABLE IF EXISTS "${tableName}"`);

    // Remove from meta
    this._exec(
      `DELETE FROM _idb_stores WHERE store_name = ?`,
      [name]
    );
    this._exec(
      `DELETE FROM _idb_indexes WHERE store_name = ?`,
      [name]
    );

    this._objectStores.delete(name);
  }

  /**
   * Create a transaction for the given object stores.
   */
  transaction(storeNames: string | string[], mode?: IDBTransactionMode): IDBTransaction {
    this._checkClosed();
    const names = Array.isArray(storeNames) ? storeNames : [storeNames];

    // Verify all stores exist
    for (const name of names) {
      if (!this._objectStores.has(name)) {
        throw new DOMException(
          `Object store "${name}" does not exist`,
          'NotFoundError',
        );
      }
    }

    // The transaction manages its own lifecycle: it stays active through the
    // creating task and each bound request's event dispatch, then auto-commits
    // once idle (see IDBTransaction). This keeps requests chained through nested
    // onsuccess handlers inside a single BEGIN/COMMIT.
    return new IDBTransaction(this, names, mode ?? 'readonly');
  }

  /**
   * Close the database connection.
   */
  close(): void {
    if (this._closed) return;
    this._closed = true;
    if (this._sqliteDb && this._sqliteDb.close) {
      this._sqliteDb.close();
    }
    // Evict the factory's cache entry for this connection. Without this, a
    // later open() would reuse the now-closed SQLite handle and fail on every
    // statement until the process restarts.
    if (this._factory && this._factory._handleConnectionClose) {
      this._factory._handleConnectionClose(this.name, this._sqliteDb);
    }
    if (this.onclose) {
      const event = { type: 'close', target: this };
      this.onclose(event);
    }
  }

  // ================================================================
  // Internal SQLite operations
  // ================================================================

  /** @internal */
  _initMeta(): void {
    this._exec(`
      CREATE TABLE IF NOT EXISTS _idb_meta (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `);
    this._exec(`
      CREATE TABLE IF NOT EXISTS _idb_stores (
        store_name TEXT PRIMARY KEY,
        key_path TEXT,
        auto_increment INTEGER DEFAULT 0
      )
    `);
    this._exec(`
      CREATE TABLE IF NOT EXISTS _idb_indexes (
        store_name TEXT,
        index_name TEXT,
        key_path TEXT,
        unique_flag INTEGER DEFAULT 0,
        multi_entry INTEGER DEFAULT 0,
        PRIMARY KEY (store_name, index_name)
      )
    `);
  }

  /** @internal */
  _loadStoreDefinitions(): void {
    const stores = this._all('SELECT store_name, key_path, auto_increment FROM _idb_stores');
    for (const row of stores) {
      const keyPath = row.key_path ? JSON.parse(row.key_path) : null;
      const opts: IDBObjectStoreParameters = {
        keyPath,
        autoIncrement: !!row.auto_increment,
      };
      const indexes = new Map<string, any>();

      // Load indexes for this store
      const idxRows = this._all(
        'SELECT index_name, key_path, unique_flag, multi_entry FROM _idb_indexes WHERE store_name = ?',
        [row.store_name]
      );
      for (const idx of idxRows) {
        indexes.set(idx.index_name, {
          keyPath: JSON.parse(idx.key_path),
          unique: !!idx.unique_flag,
          multiEntry: !!idx.multi_entry,
        });
      }

      this._objectStores.set(row.store_name, { options: opts, indexes });
    }
  }

  /** @internal */
  _saveStoreMeta(name: string, options: IDBObjectStoreParameters): void {
    this._exec(
      `INSERT OR REPLACE INTO _idb_stores (store_name, key_path, auto_increment) VALUES (?, ?, ?)`,
      [name, JSON.stringify(options.keyPath), options.autoIncrement ? 1 : 0]
    );
  }

  /** @internal */
  _saveIndexMeta(storeName: string, indexName: string, keyPath: string | string[], options: any): void {
    this._exec(
      `INSERT OR REPLACE INTO _idb_indexes (store_name, index_name, key_path, unique_flag, multi_entry) VALUES (?, ?, ?, ?, ?)`,
      [storeName, indexName, JSON.stringify(keyPath), options.unique ? 1 : 0, options.multiEntry ? 1 : 0]
    );
    // Update in-memory definition
    const storeInfo = this._objectStores.get(storeName);
    if (storeInfo) {
      storeInfo.indexes.set(indexName, {
        keyPath,
        unique: options.unique ?? false,
        multiEntry: options.multiEntry ?? false,
      });
    }
  }

  /** @internal */
  _deleteIndexMeta(storeName: string, indexName: string): void {
    this._exec(
      `DELETE FROM _idb_indexes WHERE store_name = ? AND index_name = ?`,
      [storeName, indexName]
    );
    const storeInfo = this._objectStores.get(storeName);
    if (storeInfo) {
      storeInfo.indexes.delete(indexName);
    }
  }

  /** @internal - Get an object store instance for a transaction */
  _getObjectStore(name: string, transaction: IDBTransaction): IDBObjectStore | null {
    const storeInfo = this._objectStores.get(name);
    if (!storeInfo) return null;

    const store = new IDBObjectStore(name, storeInfo.options, transaction, this);

    // Restore indexes
    for (const [indexName, indexDef] of storeInfo.indexes) {
      const idx = new IDBIndex(indexName, indexDef.keyPath, indexDef, store);
      store._indexes.set(indexName, idx);
    }

    return store;
  }

  /**
   * @internal - Allocate the next autoIncrement key for a store.
   *
   * The current key-generator value is computed once (lazily, from the table's
   * existing keys) and then cached on the store definition, which outlives
   * individual transactions. This avoids re-scanning every key on each
   * `transaction.objectStore()` call.
   */
  _nextAutoIncrement(name: string, tableName: string): number {
    const info = this._objectStores.get(name);
    if (!info) return 1;
    if (info.autoIncrementValue === undefined) {
      info.autoIncrementValue = this._computeAutoIncrementBase(tableName);
    }
    info.autoIncrementValue += 1;
    return info.autoIncrementValue;
  }

  /**
   * @internal - Keep the key generator at least as large as an explicit numeric
   * key, so a later generated key cannot collide with it (per spec).
   */
  _noteExplicitKey(name: string, key: any): void {
    if (typeof key !== 'number' || !Number.isFinite(key)) return;
    const info = this._objectStores.get(name);
    if (!info) return;
    if (info.autoIncrementValue === undefined) {
      info.autoIncrementValue = this._computeAutoIncrementBase(
        `idb_store_${sanitizeName(name)}`,
      );
    }
    info.autoIncrementValue = Math.max(info.autoIncrementValue, Math.floor(key));
  }

  /** @internal - Reset a store's cached key generator (after clear()). */
  _resetAutoIncrement(name: string): void {
    const info = this._objectStores.get(name);
    if (info) info.autoIncrementValue = 0;
  }

  /**
   * @internal - Largest numeric key currently in the table. Numeric keys are
   * serialized as bare JSON numbers (e.g. `5`), so the `GLOB '[-0-9]*'` filter
   * selects only them and `MAX(CAST(... AS REAL))` finds the largest without
   * loading and parsing every key in JS.
   */
  _computeAutoIncrementBase(tableName: string): number {
    try {
      const row = this._get(
        `SELECT MAX(CAST(key AS REAL)) AS m FROM "${tableName}" WHERE key GLOB '[-0-9]*'`,
      );
      const m = row && row.m != null ? Number(row.m) : 0;
      return Number.isFinite(m) && m > 0 ? Math.floor(m) : 0;
    } catch (_) {
      return 0;
    }
  }

  /** @internal */
  _checkClosed(): void {
    if (this._closed) {
      throw new DOMException(
        'Database connection is closed',
        'InvalidStateError',
      );
    }
  }

  // ================================================================
  // SQLite execution wrappers
  // ================================================================

  /** @internal - Execute a SQL statement */
  _exec(sql: string, params?: any[]): void {
    if (this._sqliteDb.exec) {
      if (params && params.length > 0) {
        this._sqliteDb.exec(sql, ...params);
      } else {
        this._sqliteDb.exec(sql);
      }
    } else if (this._sqliteDb.run) {
      if (params && params.length > 0) {
        this._sqliteDb.run(sql, ...params);
      } else {
        this._sqliteDb.run(sql);
      }
    }
  }

  /** @internal - Query a single row */
  _get(sql: string, params?: any[]): any {
    if (this._sqliteDb.query) {
      const stmt = this._sqliteDb.query(sql);
      return params ? stmt.get(...params) : stmt.get();
    }
    if (this._sqliteDb.prepare) {
      const stmt = this._sqliteDb.prepare(sql);
      return params ? stmt.get(...params) : stmt.get();
    }
    return null;
  }

  /** @internal - Query all rows */
  _all(sql: string, params?: any[]): any[] {
    if (this._sqliteDb.query) {
      const stmt = this._sqliteDb.query(sql);
      return params ? stmt.all(...params) : stmt.all();
    }
    if (this._sqliteDb.prepare) {
      const stmt = this._sqliteDb.prepare(sql);
      return params ? stmt.all(...params) : stmt.all();
    }
    return [];
  }
}
