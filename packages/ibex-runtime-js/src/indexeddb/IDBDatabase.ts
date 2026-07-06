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
import { deserializeKey, encodeOrderedKey } from './serialization';
import {
  DOMException,
  makeDOMStringList,
  storeTableName,
  indexTableName,
  legacyStoreTableName,
  legacyIndexTableName,
} from './utils';

/**
 * @internal - State shared by every open connection (IDBDatabase) to one
 * database name. (ENG-23117)
 *
 * open() previously handed each connection the same raw SQLite handle with no
 * coordination: close() on one connection closed the handle under its
 * siblings, each connection kept its own autoIncrement/migration caches
 * (handing out colliding generated keys), and transactions from any
 * connection silently interleaved inside one SQLite BEGIN. Everything a
 * database NAME (rather than one connection) owns now lives here:
 *
 *  - the SQLite handle, refcounted — it closes when the last connection
 *    closes and any in-flight transactions have drained;
 *  - the transaction scheduler — one transaction at a time, in creation
 *    order, across ALL connections (see IDBTransaction);
 *  - the autoIncrement key generators and the keyenc/index-table migration
 *    memos (ENG-22999 / ENG-23016), with a pre-transaction snapshot so a
 *    rollback restores them (rolled-back lazy DDL must also roll back the
 *    memo that says it happened).
 */
export class SharedConnectionState {
  sqliteDb: any;
  /** The database's current (persisted) version. */
  version: number;
  /** Open connections; the SQLite handle closes when the last one closes. */
  connections: Set<IDBDatabase> = new Set();
  /** Cached autoIncrement key generators, keyed by store name. */
  autoIncrementValues: Map<string, number> = new Map();
  /** Store tables whose keyenc column/index has been ensured. (ENG-22999) */
  keyencReady: Set<string> = new Set();
  /** Stores whose companion index table has been ensured. (ENG-23016) */
  indexDataReady: Set<string> = new Set();
  /** True once the underlying SQLite handle has been closed. */
  closed = false;
  /** Invoked when the handle actually closes, so IDBFactory evicts its cache. */
  onClosed: (() => void) | null = null;

  private _txCurrent: IDBTransaction | null = null;
  private _txQueue: IDBTransaction[] = [];
  private _snapshot: {
    ai: Map<string, number>;
    keyenc: Set<string>;
    idx: Set<string>;
  } | null = null;

  constructor(sqliteDb: any, version: number) {
    this.sqliteDb = sqliteDb;
    this.version = version;
  }

  /**
   * Start a transaction now if the connection is free, else queue it. The
   * scheduler runs one transaction at a time in creation order — see the
   * IDBTransaction header for why this is required for atomicity/isolation.
   */
  scheduleTransaction(tx: IDBTransaction): void {
    if (this._txCurrent === null) {
      this._txCurrent = tx;
      tx._start();
    } else {
      this._txQueue.push(tx);
    }
  }

  /** A transaction committed or aborted; hand the connection to the next one. */
  transactionFinished(tx: IDBTransaction): void {
    if (this._txCurrent === tx) {
      this._txCurrent = this._txQueue.shift() ?? null;
      if (this._txCurrent) {
        this._txCurrent._start();
      }
    } else {
      // Aborted while still queued.
      const i = this._txQueue.indexOf(tx);
      if (i >= 0) this._txQueue.splice(i, 1);
    }
    this._maybeCloseHandle();
  }

  /** Snapshot the caches at BEGIN so a rollback can restore them. */
  snapshotCaches(): void {
    this._snapshot = {
      ai: new Map(this.autoIncrementValues),
      keyenc: new Set(this.keyencReady),
      idx: new Set(this.indexDataReady),
    };
  }

  /** Restore the pre-transaction caches after a ROLLBACK. */
  restoreCaches(): void {
    if (this._snapshot) {
      this.autoIncrementValues = this._snapshot.ai;
      this.keyencReady = this._snapshot.keyenc;
      this.indexDataReady = this._snapshot.idx;
      this._snapshot = null;
    }
  }

  /** Discard the snapshot after a successful COMMIT. */
  discardSnapshot(): void {
    this._snapshot = null;
  }

  /** A connection closed; close the handle once the last one is gone. */
  connectionClosed(db: IDBDatabase): void {
    this.connections.delete(db);
    this._maybeCloseHandle();
  }

  /** Close the handle if nothing references it (failed sole open, etc.). */
  releaseIfUnused(): void {
    this._maybeCloseHandle();
  }

  /** deleteDatabase force-closes the handle regardless of connections. */
  forceClose(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.sqliteDb?.close?.();
    } catch (_) { /* already closed */ }
    if (this.onClosed) this.onClosed();
  }

  private _maybeCloseHandle(): void {
    if (this.closed) return;
    if (this.connections.size > 0) return;
    if (this._txCurrent !== null || this._txQueue.length > 0) return;
    this.closed = true;
    if (this.sqliteDb && this.sqliteDb.close) {
      this.sqliteDb.close();
    }
    if (this.onClosed) this.onClosed();
  }
}

export class IDBDatabase {
  readonly name: string;
  private _version: number;
  private _objectStores: Map<string, { options: IDBObjectStoreParameters; indexes: Map<string, any> }> = new Map();
  private _closed = false;
  /** @internal - Shared per-database-name state (SQLite handle, scheduler, caches) */
  _shared: SharedConnectionState;
  /** @internal - SQLite database wrapper (the shared handle) */
  _sqliteDb: any;
  /** @internal - Owning IDBFactory */
  _factory: any = null;
  /** @internal - The active versionchange transaction during upgradeneeded, if any */
  _upgradeTransaction: IDBTransaction | null = null;
  /** @internal - EventTarget listeners keyed by event type */
  private _listeners: Record<string, Function[]> = {};

  onclose: ((event: any) => void) | null = null;
  onversionchange: ((event: any) => void) | null = null;
  onerror: ((event: any) => void) | null = null;
  onabort: ((event: any) => void) | null = null;

  constructor(name: string, version: number, shared: SharedConnectionState, factory?: any) {
    this.name = name;
    this._version = version;
    this._shared = shared;
    this._sqliteDb = shared.sqliteDb;
    this._factory = factory ?? null;
    shared.connections.add(this);

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

  /**
   * @internal - Store tables whose order-preserving `keyenc` column + index
   * have already been ensured/backfilled, so the check runs at most once per
   * store rather than on every objectStore() call. Shared across sibling
   * connections and snapshot/restored around rollbacks. (ENG-22999 / ENG-23117)
   */
  get _keyencReady(): Set<string> {
    return this._shared.keyencReady;
  }

  /**
   * @internal - Store tables whose per-index companion table has been ensured
   * (and, for legacy databases, backfilled). Mirrors `_keyencReady`.
   * (ENG-23016 / ENG-23117)
   */
  get _indexDataReady(): Set<string> {
    return this._shared.indexDataReady;
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
    // Guard: only allowed inside an ACTIVE versionchange (upgradeneeded)
    // transaction. The previous check (`_upgradeTransaction && state !==
    // 'active'`) PASSED whenever no upgrade was running at all, letting normal
    // runtime code mutate the schema outside any transaction. (ENG-23117)
    if (!this._upgradeTransaction || this._upgradeTransaction._state !== 'active') {
      throw new DOMException(
        'createObjectStore can only be called during an upgrade (versionchange) transaction',
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

    const txn = this._upgradeTransaction;
    // The versionchange transaction's scope covers every store, including ones
    // created during this upgrade — the canonical
    // `e.target.transaction.objectStore(justCreated)` must work. (ENG-23117)
    txn._addToScope(name);
    const store = new IDBObjectStore(name, opts, txn, this);
    return store;
  }

  /**
   * Delete an object store. Only valid during upgradeneeded.
   */
  deleteObjectStore(name: string): void {
    // Guard: same shape as createObjectStore — the old inverted check let any
    // runtime code DROP a store's tables outside any transaction. (ENG-23117)
    if (!this._upgradeTransaction || this._upgradeTransaction._state !== 'active') {
      throw new DOMException(
        'deleteObjectStore can only be called during an upgrade (versionchange) transaction',
        'InvalidStateError',
      );
    }

    if (!this._objectStores.has(name)) {
      throw new DOMException(
        `Object store "${name}" does not exist`,
        'NotFoundError',
      );
    }

    // Drop the SQLite table and its per-index companion table. (ENG-23016)
    // Also drop the legacy-sanitizer locations for names whose encoding
    // changed, in case the store was never accessed (hence never migrated)
    // on this build. (ENG-23134)
    const tableName = storeTableName(name);
    const idxTableName = indexTableName(name);
    this._exec(`DROP TABLE IF EXISTS "${tableName}"`);
    this._exec(`DROP TABLE IF EXISTS "${idxTableName}"`);
    const legacyTable = legacyStoreTableName(name);
    if (legacyTable !== tableName && !this._tableNameClaimed(legacyTable, name)) {
      this._exec(`DROP TABLE IF EXISTS "${legacyTable}"`);
      this._exec(`DROP TABLE IF EXISTS "${legacyIndexTableName(name)}"`);
    }

    // Remove from meta
    this._exec(
      `DELETE FROM _idb_stores WHERE store_name = ?`,
      [name]
    );
    this._exec(
      `DELETE FROM _idb_indexes WHERE store_name = ?`,
      [name]
    );
    this._exec(`DELETE FROM _idb_meta WHERE key = ?`, [`idxdata:${name}`]);

    this._shared.keyencReady.delete(tableName);
    this._shared.indexDataReady.delete(idxTableName);
    // Deleting a store resets its key generator (per spec).
    this._shared.autoIncrementValues.delete(name);
    this._objectStores.delete(name);
    this._upgradeTransaction._removeFromScope(name);
  }

  /**
   * Create a transaction for the given object stores.
   */
  transaction(storeNames: string | string[], mode?: IDBTransactionMode): IDBTransaction {
    this._checkClosed();
    if (this._upgradeTransaction) {
      throw new DOMException(
        'A versionchange transaction is running',
        'InvalidStateError',
      );
    }
    const m = mode ?? 'readonly';
    // Applications may not create versionchange transactions; those exist only
    // inside upgradeneeded. (ENG-23117)
    if (m !== 'readonly' && m !== 'readwrite') {
      throw new TypeError(
        `The mode provided ('${m}') is not one of 'readonly' or 'readwrite'.`,
      );
    }
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
    return new IDBTransaction(this, names, m);
  }

  /**
   * Close the database connection.
   *
   * The underlying SQLite handle is refcounted: it closes only when the LAST
   * connection to this database name closes (and any in-flight transactions
   * have drained). Closing it eagerly bricked sibling connections handed out
   * by a second open(). (ENG-23117)
   */
  close(): void {
    if (this._closed) return;
    this._closed = true;
    this._shared.connectionClosed(this);
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

  // ================================================================
  // Transaction scheduling & cache snapshots (ENG-23117)
  // ================================================================

  /** @internal - Forward to the shared connection scheduler. */
  _scheduleTransaction(tx: IDBTransaction): void {
    this._shared.scheduleTransaction(tx);
  }

  /** @internal - Forward to the shared connection scheduler. */
  _transactionFinished(tx: IDBTransaction): void {
    this._shared.transactionFinished(tx);
  }

  /** @internal - Snapshot shared caches at BEGIN (see SharedConnectionState). */
  _beginTxnSnapshot(): void {
    this._shared.snapshotCaches();
  }

  /** @internal - Restore shared caches after ROLLBACK. */
  _rollbackTxnSnapshot(): void {
    this._shared.restoreCaches();
  }

  /** @internal - Discard the snapshot after COMMIT. */
  _commitTxnSnapshot(): void {
    this._shared.discardSnapshot();
  }

  /**
   * @internal - Allocate the next autoIncrement key for a store.
   *
   * The current key-generator value is computed once (lazily, from the table's
   * existing keys) and then cached on the SHARED per-name state, so sibling
   * connections draw from one generator and cannot hand out colliding keys.
   * A rollback restores the generator via the transaction snapshot (per spec,
   * aborting a transaction reverts its key-generator advances). (ENG-23117)
   */
  _nextAutoIncrement(name: string, tableName: string): number {
    let value = this._shared.autoIncrementValues.get(name);
    if (value === undefined) {
      value = this._computeAutoIncrementBase(tableName);
    }
    value += 1;
    this._shared.autoIncrementValues.set(name, value);
    return value;
  }

  /**
   * @internal - Keep the key generator at least as large as an explicit numeric
   * key, so a later generated key cannot collide with it (per spec).
   */
  _noteExplicitKey(name: string, key: any): void {
    if (typeof key !== 'number' || !Number.isFinite(key)) return;
    let value = this._shared.autoIncrementValues.get(name);
    if (value === undefined) {
      value = this._computeAutoIncrementBase(storeTableName(name));
    }
    this._shared.autoIncrementValues.set(name, Math.max(value, Math.floor(key)));
  }

  /**
   * @internal - Whether a SQLite table name is the CURRENT backing table of
   * some other object store. Guards the legacy-table migration/cleanup paths:
   * under the old lossy sanitizer, "user-data"'s table may be the very table
   * that live store "user_data" still uses — renaming or dropping it for
   * "user-data" would destroy "user_data". Compared case-insensitively,
   * because SQLite treats ASCII identifiers case-insensitively (dropping
   * "idb_store_Settings" would hit "idb_store_settings"). (ENG-23134)
   */
  _tableNameClaimed(tableName: string, exceptStoreName: string): boolean {
    const wanted = tableName.toLowerCase();
    for (const n of this._objectStores.keys()) {
      if (n === exceptStoreName) continue;
      if (
        storeTableName(n).toLowerCase() === wanted ||
        indexTableName(n).toLowerCase() === wanted
      ) {
        return true;
      }
    }
    return false;
  }

  /**
   * @internal - Ensure the order-preserving `keyenc` column and its index exist
   * on a store table, migrating (ALTER + backfill) any store created before
   * this column was introduced. The result is memoized on the shared state so
   * the PRAGMA check is paid at most once per store, keeping it off the hot
   * path (mirrors the autoIncrement caching above). Freshly created tables
   * already declare `keyenc`, so they only pay the CREATE INDEX. (ENG-22999)
   */
  _ensureKeyEnc(tableName: string): void {
    if (this._shared.keyencReady.has(tableName)) return;

    const cols = this._all(`PRAGMA table_info("${tableName}")`);
    const hasKeyenc = cols.some((c: any) => c.name === 'keyenc');
    if (!hasKeyenc) {
      this._exec(`ALTER TABLE "${tableName}" ADD COLUMN keyenc TEXT`);
      // Backfill the ordered encoding for every pre-existing row. One-time O(n)
      // cost on first open of a legacy store; afterwards all writes maintain it.
      const rows = this._all(`SELECT key FROM "${tableName}"`);
      for (const r of rows) {
        this._exec(
          `UPDATE "${tableName}" SET keyenc = ? WHERE key = ?`,
          [encodeOrderedKey(deserializeKey(r.key)), r.key],
        );
      }
    }
    this._exec(
      `CREATE INDEX IF NOT EXISTS "${tableName}_keyenc" ON "${tableName}"(keyenc)`,
    );
    this._shared.keyencReady.add(tableName);
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
