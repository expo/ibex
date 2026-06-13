/**
 * SQLite Database for the Exact runtime.
 *
 * API matches bun:sqlite's Database class with cr-sqlite extension support.
 *
 * @see https://bun.sh/docs/api/sqlite
 * @see https://vlcn.io/docs/cr-sqlite/intro
 */

import { Statement, type Changes } from './Statement';

const g = globalThis as any;

export interface DatabaseOptions {
  /** Open the database as read-only. */
  readonly?: boolean;
  /** Create the database if it doesn't exist (default: true). */
  create?: boolean;
  /** Open for read-write (default: true). */
  readwrite?: boolean;
  /** Return integers as BigInt instead of Number. */
  safeIntegers?: boolean;
  /** Strict parameter binding (no prefix needed, errors on missing params). */
  strict?: boolean;
}

export class Database {
  /** @internal */
  _handle: any;
  /** @internal */
  _closed = false;
  /** @internal */
  _queryCache = new Map<string, Statement>();
  /** @internal */
  _options: DatabaseOptions;
  /** @internal */
  _crSqliteLoaded = false;

  /** The filename of the database. */
  readonly filename: string;

  /**
   * Create or open a SQLite database.
   *
   * @param filename Path to the database file.
   *   - `:memory:` or `""` or omitted for in-memory database
   * @param options Database options or raw SQLite open flags
   */
  constructor(filename?: string, options?: number | DatabaseOptions) {
    this.filename = filename ?? ':memory:';

    if (typeof options === 'number') {
      this._options = {};
    } else {
      this._options = options ?? {};
    }

    if (!g.__exactSqliteOpen) {
      throw new Error(
        'exact:sqlite native bridge not available. ' +
        'The exact:sqlite module requires the Exact runtime with SQLite support.'
      );
    }

    const flags = typeof options === 'number' ? options : undefined;
    this._handle = g.__exactSqliteOpen(this.filename, {
      readonly: this._options.readonly ?? false,
      create: this._options.create ?? true,
      readwrite: this._options.readwrite ?? true,
      safeIntegers: this._options.safeIntegers ?? false,
      flags,
    });

    // Enable WAL mode by default for better concurrent access
    this.run('PRAGMA journal_mode = WAL');
    this.run('PRAGMA foreign_keys = ON');
  }

  /**
   * The native SQLite handle.
   */
  get handle(): any {
    return this._handle;
  }

  /**
   * Whether the database is currently in a transaction.
   */
  get inTransaction(): boolean {
    this._checkClosed();
    if (g.__exactSqliteInTransaction) {
      return g.__exactSqliteInTransaction(this._handle);
    }
    return false;
  }

  /**
   * Prepare and cache a SQL statement.
   * Returns the cached statement if the same SQL was previously queried.
   */
  query<R = any, P extends any[] = any[]>(sql: string): Statement<R, P> {
    this._checkClosed();
    let stmt = this._queryCache.get(sql);
    if (!stmt) {
      stmt = new Statement(this._handle, sql);
      this._queryCache.set(sql, stmt);
    }
    return stmt as Statement<R, P>;
  }

  /**
   * Prepare a SQL statement WITHOUT caching.
   * Creates a fresh Statement each time.
   */
  prepare<R = any, P extends any[] = any[]>(sql: string): Statement<R, P> {
    this._checkClosed();
    return new Statement<R, P>(this._handle, sql);
  }

  /**
   * Execute a SQL statement directly.
   * Supports multi-statement SQL (e.g., "SELECT 1; SELECT 2;").
   *
   * @returns Changes info with `changes` and `lastInsertRowid`
   */
  run(sql: string, ...bindings: any[]): Changes {
    this._checkClosed();
    if (g.__exactSqliteExec) {
      const params = bindings.length === 1 && typeof bindings[0] === 'object' && bindings[0] !== null && !(bindings[0] instanceof Uint8Array)
        ? bindings[0]
        : bindings.length > 0 ? bindings : undefined;
      return g.__exactSqliteExec(this._handle, sql, params);
    }
    // Fallback: use prepare + run
    const stmt = this.prepare(sql);
    try {
      return stmt.run(...bindings);
    } finally {
      stmt.finalize();
    }
  }

  /**
   * Alias for run().
   */
  exec(sql: string, ...bindings: any[]): Changes {
    return this.run(sql, ...bindings);
  }

  /**
   * Create a transaction wrapper function.
   *
   * @returns A callable function that wraps execution in BEGIN/COMMIT.
   *   If the function throws, the transaction is rolled back.
   *   The returned function has `.deferred()`, `.immediate()`, and `.exclusive()` variants.
   */
  transaction<T extends (...args: any[]) => any>(fn: T): T & {
    deferred: T;
    immediate: T;
    exclusive: T;
  } {
    this._checkClosed();
    const db = this;

    const wrapTransaction = (beginStatement: string) => {
      return function (this: any, ...args: any[]) {
        // Nested transactions use savepoints
        if (db.inTransaction) {
          const savepointName = `_sp_${Date.now()}_${Math.random().toString(36).slice(2)}`;
          db.run(`SAVEPOINT "${savepointName}"`);
          try {
            const result = fn.apply(this, args);
            db.run(`RELEASE "${savepointName}"`);
            return result;
          } catch (e) {
            db.run(`ROLLBACK TO "${savepointName}"`);
            db.run(`RELEASE "${savepointName}"`);
            throw e;
          }
        }

        db.run(beginStatement);
        try {
          const result = fn.apply(this, args);
          db.run('COMMIT');
          return result;
        } catch (e) {
          db.run('ROLLBACK');
          throw e;
        }
      } as any;
    };

    const txnFn = wrapTransaction('BEGIN') as any;
    txnFn.deferred = wrapTransaction('BEGIN DEFERRED');
    txnFn.immediate = wrapTransaction('BEGIN IMMEDIATE');
    txnFn.exclusive = wrapTransaction('BEGIN EXCLUSIVE');

    return txnFn;
  }

  /**
   * Close the database connection.
   * @param throwOnError If true, throws on close errors (default: false)
   */
  close(throwOnError = false): void {
    if (this._closed) return;

    // Finalize cr-sqlite before closing (needs db still open)
    if (this._crSqliteLoaded) {
      try {
        this.run('SELECT crsql_finalize()');
      } catch {
        // Ignore errors during cleanup
      }
    }

    this._closed = true;

    // Finalize cached statements
    for (const stmt of this._queryCache.values()) {
      stmt.finalize();
    }
    this._queryCache.clear();

    if (g.__exactSqliteClose) {
      try {
        g.__exactSqliteClose(this._handle);
      } catch (e) {
        if (throwOnError) throw e;
      }
    }
  }

  /**
   * Serialize the database to a Buffer/Uint8Array.
   * @param name Database name (default: "main")
   */
  serialize(name?: string): Uint8Array {
    this._checkClosed();
    if (!g.__exactSqliteSerialize) {
      throw new Error('Database serialization not supported in this build');
    }
    return g.__exactSqliteSerialize(this._handle, name ?? 'main');
  }

  /**
   * Load a SQLite extension.
   * @param path Path to the extension shared library
   * @param entryPoint Optional entry point function name
   */
  loadExtension(path: string, entryPoint?: string): void {
    this._checkClosed();
    if (!g.__exactSqliteLoadExtension) {
      throw new Error('Extension loading not supported in this build');
    }
    g.__exactSqliteLoadExtension(this._handle, path, entryPoint);
  }

  /**
   * Advanced sqlite3_file_control interface.
   */
  fileControl(cmd: number, value?: any): any;
  fileControl(zDbName: string, cmd: number, value?: any): any;
  fileControl(...args: any[]): any {
    this._checkClosed();
    if (!g.__exactSqliteFileControl) {
      throw new Error('fileControl not supported in this build');
    }
    return g.__exactSqliteFileControl(this._handle, ...args);
  }

  // ================================================================
  // cr-sqlite extension support
  // ================================================================

  /**
   * Load and initialize the cr-sqlite extension for CRDT-based replication.
   *
   * After calling this, you can use:
   * - `db.run("SELECT crsql_as_crr('table_name')")` to make a table a CRR
   * - `db.query("SELECT * FROM crsql_changes WHERE db_version > ?")` to get changes
   * - `db.run("INSERT INTO crsql_changes ...")` to apply changes from another peer
   *
   * @see https://vlcn.io/docs/cr-sqlite/intro
   */
  enableCrSqlite(): void {
    this._checkClosed();
    if (this._crSqliteLoaded) return;

    if (g.__exactCrSqlitePath) {
      this.loadExtension(g.__exactCrSqlitePath());
    } else if (g.__exactSqliteLoadCrSqlite) {
      g.__exactSqliteLoadCrSqlite(this._handle);
    } else {
      throw new Error(
        'cr-sqlite extension not available. ' +
        'The Exact runtime must be built with cr-sqlite support.'
      );
    }
    this._crSqliteLoaded = true;
  }

  /**
   * Get the unique site ID for this database (cr-sqlite).
   * Each database instance has a unique identifier for replication.
   */
  getSiteId(): Uint8Array {
    this._checkClosed();
    this._requireCrSqlite();
    const result = this.query<{ id: Uint8Array }>('SELECT crsql_site_id() as id').get();
    return result!.id;
  }

  /**
   * Get the current database version (cr-sqlite logical clock).
   */
  getDbVersion(): number | bigint {
    this._checkClosed();
    this._requireCrSqlite();
    const result = this.query<{ version: number }>('SELECT crsql_db_version() as version').get();
    return result!.version;
  }

  /**
   * Mark a table as a Conflict-free Replicated Relation (CRR).
   * This adds CRDT metadata and triggers for automatic conflict resolution.
   *
   * @param tableName Name of the existing table to make a CRR
   */
  markAsCrr(tableName: string): void {
    this._checkClosed();
    this._requireCrSqlite();
    this.run(`SELECT crsql_as_crr('${tableName}')`);
  }

  /**
   * Get changesets since a given database version.
   * Used for syncing with other peers.
   *
   * @param sinceVersion Get changes after this version (0 for all changes)
   * @param excludeSiteId Optional site ID to exclude (optimization for bilateral sync)
   */
  getChanges(sinceVersion: number | bigint = 0, excludeSiteId?: Uint8Array): any[] {
    this._checkClosed();
    this._requireCrSqlite();

    if (excludeSiteId) {
      return this.query(
        `SELECT "table", "pk", "cid", "val", "col_version", "db_version", "site_id", "cl", "seq"
         FROM crsql_changes
         WHERE db_version > ? AND site_id IS NOT ?`
      ).all(sinceVersion, excludeSiteId);
    }

    return this.query(
      `SELECT "table", "pk", "cid", "val", "col_version", "db_version", "site_id", "cl", "seq"
       FROM crsql_changes
       WHERE db_version > ?`
    ).all(sinceVersion);
  }

  /**
   * Apply a changeset from another peer.
   * The changeset should be the output of getChanges() from another database.
   *
   * @param changes Array of change rows from getChanges()
   */
  applyChanges(changes: any[]): void {
    this._checkClosed();
    this._requireCrSqlite();

    const insert = this.prepare(
      `INSERT INTO crsql_changes ("table", "pk", "cid", "val", "col_version", "db_version", "site_id", "cl", "seq")
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const applyAll = this.transaction((changes: any[]) => {
      for (const change of changes) {
        insert.run(
          change.table, change.pk, change.cid, change.val,
          change.col_version, change.db_version, change.site_id,
          change.cl, change.seq
        );
      }
    });

    try {
      applyAll(changes);
    } finally {
      insert.finalize();
    }
  }

  // ================================================================
  // Static methods
  // ================================================================

  /**
   * Create or open a SQLite database (alias for constructor).
   */
  static open(filename?: string, options?: number | DatabaseOptions): Database {
    return new Database(filename, options);
  }

  /**
   * Create a database from serialized data.
   */
  static deserialize(data: Uint8Array, options?: boolean | DatabaseOptions): Database {
    if (!g.__exactSqliteDeserialize) {
      throw new Error('Database deserialization not supported in this build');
    }

    const isReadOnly = typeof options === 'boolean' ? options : (options as DatabaseOptions)?.readonly ?? false;
    const handle = g.__exactSqliteDeserialize(data, isReadOnly);

    const db = Object.create(Database.prototype) as Database;
    db._handle = handle;
    db._closed = false;
    db._queryCache = new Map();
    db._options = typeof options === 'object' ? options : { readonly: isReadOnly };
    (db as any).filename = ':memory:';
    db._crSqliteLoaded = false;
    return db;
  }

  [Symbol.dispose](): void {
    this.close();
  }

  get [Symbol.toStringTag](): string {
    return 'Database';
  }

  // ================================================================
  // Internal helpers
  // ================================================================

  /** @internal */
  private _checkClosed(): void {
    if (this._closed) {
      throw new Error('Database is closed');
    }
  }

  /** @internal */
  private _requireCrSqlite(): void {
    if (!this._crSqliteLoaded) {
      throw new Error(
        'cr-sqlite is not loaded. Call db.enableCrSqlite() first.'
      );
    }
  }
}

export default Database;
